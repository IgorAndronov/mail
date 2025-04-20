package smtpserver

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/yourusername/emailserver/internal/models"
)

/* ------------------------------------------------------------------
   Session stores a reference to AppAPI (defined in backend.go)
-------------------------------------------------------------------*/

type Session struct {
	app         AppAPI
	from        string
	to          []string
	data        []byte
	currentSize int
}

func NewSession(a AppAPI) *Session { return &Session{app: a} }

/* ======================  AUTH PLAIN  ============================= */

func (s *Session) AuthPlain(username, password string) error {
	var u models.User
	if err := s.app.GetDB().Get(&u, "SELECT * FROM users WHERE email=$1", username); err != nil {
		return errors.New("authentication failed")
	}
	if !u.IsActive {
		return errors.New("authentication failed")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return errors.New("authentication failed")
	}
	return nil
}

/* ======================  ENVELOPE  =============================== */

func (s *Session) Mail(from string, _ *smtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	cfg := s.app.GetConfig()

	if !strings.HasSuffix(to, "@"+cfg.Domain) {
		return errors.New("recipient domain not served by this server")
	}

	var n int
	if err := s.app.GetDB().Get(&n, "SELECT COUNT(*) FROM mailboxes WHERE address=$1", to); err != nil || n == 0 {
		return errors.New("recipient not found")
	}

	if !s.app.IsEmailAllowed(s.from, to) && !s.isPermissionRequest(to) {
		return errors.New("sender not authorized to send to this recipient")
	}

	s.to = append(s.to, to)
	return nil
}

func (s *Session) isPermissionRequest(addr string) bool {
	return strings.HasPrefix(addr, "permission-") ||
		strings.HasPrefix(addr, "admin@") ||
		strings.HasPrefix(addr, "permissions@")
}

/* ======================  DATA  =================================== */

func (s *Session) Data(r io.Reader) error {
	if len(s.to) == 0 {
		return errors.New("no recipients specified")
	}

	buf, _ := io.ReadAll(r)
	s.data = buf

	for _, rcpt := range s.to {
		if err := s.storeEmail(rcpt); err != nil {
			log.Printf("Error storing email to %s: %v", rcpt, err)
		}
	}
	return nil
}

/* ======================  STORE EMAIL  ============================ */

func (s *Session) storeEmail(recipient string) error {
	cfg := s.app.GetConfig()

	raw := string(s.data)

	// crude header/body extraction (same logic as original)
	subject := "No Subject"
	if i := strings.Index(raw, "Subject: "); i != -1 {
		if j := strings.Index(raw[i:], "\r\n"); j != -1 {
			subject = raw[i+9 : i+j]
		}
	}
	body := ""
	if i := strings.Index(raw, "\r\n\r\n"); i != -1 {
		body = raw[i+4:]
	}

	/* -- special case: permission‑request email -- */
	if s.isPermissionRequest(recipient) {
		return s.processPermissionRequest(recipient, subject, body)
	}

	var mbox models.Mailbox
	if err := s.app.GetDB().Get(&mbox, "SELECT * FROM mailboxes WHERE address=$1", recipient); err != nil {
		return fmt.Errorf("mailbox not found: %w", err)
	}

	id := uuid.New().String()
	path := fmt.Sprintf("%s/%s.eml", cfg.EmailStoragePath, id)
	if err := os.WriteFile(path, s.data, 0o644); err != nil {
		return fmt.Errorf("save file: %w", err)
	}

	_, err := s.app.GetDB().Exec(`
		INSERT INTO emails
		  (id,from_address,to_address,subject,body,created_at,mailbox_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		id, s.from, recipient, subject, body, time.Now(), mbox.ID)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("save metadata: %w", err)
	}

	log.Printf("Email from %s to %s stored", s.from, recipient)
	return nil
}

/* ======================  PERMISSION FLOW  ======================= */

func (s *Session) processPermissionRequest(recipient, subject, body string) error {
	if !strings.Contains(strings.ToLower(subject), "permission request") {
		return nil
	}

	targetMailbox := ""
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "target:") {
			targetMailbox = strings.TrimSpace(strings.TrimPrefix(line, "Target:"))
			break
		}
	}
	if targetMailbox == "" {
		return fmt.Errorf("invalid permission request: no target mailbox specified")
	}

	cfg := s.app.GetConfig()
	now := time.Now()
	token := uuid.New().String()

	_, err := s.app.GetDB().Exec(`
		INSERT INTO permission_requests
		  (id,requestor_email,target_mailbox,token,created_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.New().String(), s.from, targetMailbox, token, now, now.AddDate(0, 1, 0))
	if err != nil {
		return fmt.Errorf("failed to create permission request: %w", err)
	}

	var mbox models.Mailbox
	if err := s.app.GetDB().Get(&mbox, "SELECT * FROM mailboxes WHERE address=$1", targetMailbox); err != nil {
		return fmt.Errorf("target mailbox not found: %w", err)
	}

	confirmSubj := "Permission Request Confirmation"
	confirmBody := fmt.Sprintf(
		"A user from %s has requested permission to send emails to %s.\n\n"+
			"To approve this request, click the link below:\n"+
			"http://%s:%d/api/confirm-permission/%s\n\n"+
			"This request will expire in 30 days.",
		s.from, targetMailbox, cfg.WebHost, cfg.WebPort, token,
	)

	_, err = s.app.GetDB().Exec(`
		INSERT INTO emails
		  (id,from_address,to_address,subject,body,created_at,mailbox_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New().String(), "system@"+cfg.Domain, targetMailbox,
		confirmSubj, confirmBody, now, mbox.ID)
	return err
}

/* ======================  SESSION CLEANUP  ======================= */

func (s *Session) Reset() {
	s.from, s.to, s.data, s.currentSize = "", nil, nil, 0
}

func (s *Session) Logout() error { return nil }
