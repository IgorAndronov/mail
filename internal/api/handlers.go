package api

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/gomail.v2"
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/yourusername/emailserver/internal/app"
	"github.com/yourusername/emailserver/internal/models"
	"golang.org/x/crypto/bcrypt"
)

/* ----------------------------------------------------------------
   DTO types – identical field names / JSON tags as in the original
-----------------------------------------------------------------*/

type UserRegistration struct {
	Email    string `json:"email"  binding:"required"`
	Password string `json:"password" binding:"required"`
}

type UserLogin struct {
	Email    string `json:"email"  binding:"required"`
	Password string `json:"password" binding:"required"`
}

type MailboxCreation struct {
	Address string `json:"address" binding:"required"`
}

type PermissionRequestCreation struct {
	TargetMailbox string `json:"target_mailbox" binding:"required"`
}

type OutboundEmail struct {
	From        string   `json:"from"    binding:"required,email"`
	To          string   `json:"to"      binding:"required,email"`
	Subject     string   `json:"subject" binding:"required"`
	Body        string   `json:"body"    binding:"required"`
	Attachments []string `json:"attachments,omitempty"`
}

/* ================================================================
   USER AUTHENTICATION
================================================================ */

func handleUserRegistration(a *app.App, c *gin.Context) {
	var in UserRegistration
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// validate e‑mail
	if !strings.Contains(in.Email, "@") {
		c.JSON(400, gin.H{"error": "Invalid email address"})
		return
	}
	isExternal := !strings.HasSuffix(in.Email, "@"+a.GetConfig().Domain)

	// already exists?
	var cnt int
	if err := a.GetDB().Get(&cnt, "SELECT COUNT(*) FROM users WHERE email=$1", in.Email); err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	if cnt > 0 {
		c.JSON(400, gin.H{"error": "User already exists"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	uid := uuid.New().String()
	now := time.Now()

	_, err := a.GetDB().Exec(`
		INSERT INTO users (id,email,password_hash,is_active,created_at,updated_at,is_admin,external_domain)
		VALUES ($1,$2,$3,$4,$5,$5,$6,$7)`,
		uid, in.Email, string(hash), true, now, false, isExternal)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	// default mailbox for internal users
	if !isExternal {
		mbID := uuid.New().String()
		_, _ = a.GetDB().Exec(`
			INSERT INTO mailboxes (id,address,user_id,created_at,updated_at)
			VALUES ($1,$2,$3,$4,$4)`,
			mbID, in.Email, uid, now)
	}

	c.JSON(201, gin.H{"id": uid, "message": "User registered successfully"})
}

func handleUserLogin(a *app.App, c *gin.Context) {
	var in UserLogin
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	var u models.User
	if err := a.GetDB().Get(&u, "SELECT * FROM users WHERE email=$1", in.Email); err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)) != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := a.GenerateJWT(u) // helper lives in app package; unchanged logic
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}
	c.JSON(200, gin.H{"token": token})
}

/* ================================================================
   MAILBOX MANAGEMENT
================================================================ */

func handleCreateMailbox(a *app.App, c *gin.Context) {
	userID := c.GetString("userID")

	var in MailboxCreation
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}
	if !strings.HasSuffix(in.Address, "@"+a.GetConfig().Domain) {
		c.JSON(400, gin.H{"error": "Mailbox must use domain " + a.GetConfig().Domain})
		return
	}

	var cnt int
	if err := a.GetDB().Get(&cnt, "SELECT COUNT(*) FROM mailboxes WHERE address=$1", in.Address); err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	if cnt > 0 {
		c.JSON(400, gin.H{"error": "Mailbox already exists"})
		return
	}

	mbID := uuid.New().String()
	now := time.Now()
	_, err := a.GetDB().Exec(`
		INSERT INTO mailboxes (id,address,user_id,created_at,updated_at)
		VALUES ($1,$2,$3,$4,$4)`,
		mbID, in.Address, userID, now)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create mailbox"})
		return
	}
	c.JSON(201, gin.H{"id": mbID})
}

func handleListMailboxes(a *app.App, c *gin.Context) {
	userID := c.GetString("userID")

	var mbs []models.Mailbox
	if err := a.GetDB().Select(&mbs, "SELECT * FROM mailboxes WHERE user_id=$1", userID); err != nil {
		c.JSON(500, gin.H{"error": "Failed to list mailboxes"})
		return
	}
	c.JSON(200, gin.H{"mailboxes": mbs})
}

/* ================================================================
   EMAIL OPERATIONS
================================================================ */

func handleListEmails(a *app.App, c *gin.Context) {
	userID, mbID := c.GetString("userID"), c.Param("mailboxId")

	var cnt int
	if err := a.GetDB().Get(&cnt, `
		SELECT COUNT(*) FROM mailboxes WHERE id=$1 AND user_id=$2`, mbID, userID); err != nil || cnt == 0 {
		c.JSON(403, gin.H{"error": "Unauthorized"})
		return
	}

	var emails []models.Email
	if err := a.GetDB().Select(&emails, `
		SELECT * FROM emails WHERE mailbox_id=$1 ORDER BY created_at DESC`, mbID); err != nil {
		c.JSON(500, gin.H{"error": "Failed to list emails"})
		return
	}
	c.JSON(200, gin.H{"emails": emails})
}

func handleGetEmail(a *app.App, c *gin.Context) {
	userID, mbID, emailID := c.GetString("userID"), c.Param("mailboxId"), c.Param("emailId")

	var cnt int
	if err := a.GetDB().Get(&cnt, `
		SELECT COUNT(*) FROM mailboxes WHERE id=$1 AND user_id=$2`, mbID, userID); err != nil || cnt == 0 {
		c.JSON(403, gin.H{"error": "Unauthorized"})
		return
	}

	var email models.Email
	if err := a.GetDB().Get(&email, `
		SELECT * FROM emails WHERE id=$1 AND mailbox_id=$2`, emailID, mbID); err != nil {
		c.JSON(404, gin.H{"error": "Email not found"})
		return
	}

	if email.ReadAt == nil {
		now := time.Now()
		_, _ = a.GetDB().Exec("UPDATE emails SET read_at=$1 WHERE id=$2", now, emailID)
		email.ReadAt = &now
	}

	file := fmt.Sprintf("%s/%s.eml", a.GetConfig().EmailStoragePath, emailID)
	raw, _ := os.ReadFile(file)

	c.JSON(200, gin.H{"email": email, "raw_content": string(raw)})
}

func handleDeleteEmail(a *app.App, c *gin.Context) {
	userID, mbID, emailID := c.GetString("userID"), c.Param("mailboxId"), c.Param("emailId")

	var cnt int
	if err := a.GetDB().Get(&cnt, `
		SELECT COUNT(*) FROM mailboxes WHERE id=$1 AND user_id=$2`, mbID, userID); err != nil || cnt == 0 {
		c.JSON(403, gin.H{"error": "Unauthorized"})
		return
	}
	if _, err := a.GetDB().Exec(`
		DELETE FROM emails WHERE id=$1 AND mailbox_id=$2`, emailID, mbID); err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete email"})
		return
	}

	_ = os.Remove(fmt.Sprintf("%s/%s.eml", a.GetConfig().EmailStoragePath, emailID))
	c.JSON(200, gin.H{"message": "Email deleted"})
}

/* ================================================================
   PERMISSION REQUEST FLOW
================================================================ */

func handleRequestPermission(a *app.App, c *gin.Context) {
	var in PermissionRequestCreation
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	userID := c.GetString("userID")
	var user models.User
	if err := a.GetDB().Get(&user, "SELECT * FROM users WHERE id=$1", userID); err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch user"})
		return
	}

	var cnt int
	if err := a.GetDB().Get(&cnt, "SELECT COUNT(*) FROM mailboxes WHERE address=$1", in.TargetMailbox); err != nil || cnt == 0 {
		c.JSON(400, gin.H{"error": "Target mailbox does not exist"})
		return
	}
	if err := a.GetDB().Get(&cnt, `
		SELECT COUNT(*) FROM permission_requests
		WHERE requestor_email=$1 AND target_mailbox=$2 AND approved_at IS NOT NULL AND expires_at>NOW()`,
		user.Email, in.TargetMailbox); err != nil {
		c.JSON(500, gin.H{"error": "Database error"})
		return
	}
	if cnt > 0 {
		c.JSON(400, gin.H{"error": "Permission already granted"})
		return
	}

	reqID, token := uuid.New().String(), uuid.New().String()
	now := time.Now()
	_, err := a.GetDB().Exec(`
		INSERT INTO permission_requests
		(id,requestor_email,target_mailbox,token,created_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		reqID, user.Email, in.TargetMailbox, token, now, now.AddDate(0, 1, 0))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create request"})
		return
	}

	var mailbox models.Mailbox
	_ = a.GetDB().Get(&mailbox, "SELECT * FROM mailboxes WHERE address=$1", in.TargetMailbox)

	subj := "Permission Request Confirmation"
	body := fmt.Sprintf(
		"User %s has requested permission to send emails to %s.\n\n"+
			"To approve, click:\nhttp://%s:%d/api/confirm-permission/%s\n\n"+
			"This request expires in 30 days.",
		user.Email, in.TargetMailbox, a.GetConfig().WebHost, a.GetConfig().WebPort, token)

	_, _ = a.GetDB().Exec(`
		INSERT INTO emails (id,from_address,to_address,subject,body,created_at,mailbox_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New().String(), "system@"+a.GetConfig().Domain, in.TargetMailbox,
		subj, body, now, mailbox.ID)

	c.JSON(201, gin.H{"message": "Permission request sent"})
}

func handleConfirmPermission(a *app.App, c *gin.Context) {
	token := c.Param("token")

	var pr models.PermissionRequest
	if err := a.GetDB().Get(&pr, "SELECT * FROM permission_requests WHERE token=$1", token); err != nil {
		c.JSON(404, gin.H{"error": "Request not found"})
		return
	}
	if pr.ApprovedAt != nil {
		c.JSON(400, gin.H{"error": "Already approved"})
		return
	}
	if time.Now().After(pr.ExpiresAt) {
		c.JSON(400, gin.H{"error": "Request expired"})
		return
	}

	now := time.Now()
	_, _ = a.GetDB().Exec("UPDATE permission_requests SET approved_at=$1 WHERE id=$2", now, pr.ID)

	a.AddAllowedSender(pr.TargetMailbox, pr.RequestorEmail)
	c.JSON(200, gin.H{"message": "Permission approved"})
}

func handleSendEmail(a *app.App, c *gin.Context) {

	var req OutboundEmail
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	/* 1. verify the “from” address belongs to this user */
	//userID := c.GetString("userID")
	//var cnt int
	//if err := a.GetDB().Get(&cnt,
	//	`SELECT COUNT(*) FROM mailboxes WHERE address=$1 AND user_id=$2`,
	//	req.From, userID); err != nil || cnt == 0 {
	//	c.JSON(403, gin.H{"error": "From address not owned by user"})
	//	return
	//}

	/* 2. build MIME message with gomail */
	msg := gomail.NewMessage()
	msg.SetHeader("From", req.From)
	msg.SetHeader("To", req.To)
	msg.SetHeader("Subject", req.Subject)
	msg.SetBody("text/plain", req.Body)

	for _, f := range req.Attachments {
		msg.Attach(f) // auto‑detect MIME type & encode
	}

	/* 3. dial local SMTP listener (no auth) */
	cfg := a.GetConfig()
	d := gomail.NewDialer(cfg.SMTPHost, cfg.SMTPPort, "", "")
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true} // local self‑signed ok

	if err := d.DialAndSend(msg); err != nil {
		log.Printf("DialAndSend: %v", err)
		c.JSON(500, gin.H{"error": "SMTP send failed"})
		return
	}

	c.JSON(202, gin.H{"message": "Message accepted"})
}

/* ================================================================
   ADMIN HANDLERS
================================================================ */

func handleListUsers(a *app.App, c *gin.Context) {
	var users []models.User
	if err := a.GetDB().Select(&users, "SELECT * FROM users"); err != nil {
		c.JSON(500, gin.H{"error": "Failed to list users"})
		return
	}
	c.JSON(200, gin.H{"users": users})
}

func handleAddTrustedDomain(a *app.App, c *gin.Context) {
	var in struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	for _, d := range a.GetConfig().TrustedDomains {
		if d == in.Domain {
			c.JSON(400, gin.H{"error": "Domain already trusted"})
			return
		}
	}
	a.AppendTrustedDomain(in.Domain) // helper in app package
	c.JSON(201, gin.H{"message": "Domain added"})
}

func handleRemoveTrustedDomain(a *app.App, c *gin.Context) {
	domain := c.Param("domain")
	if a.RemoveTrustedDomain(domain) { // helper returns bool
		c.JSON(200, gin.H{"message": "Domain removed"})
		return
	}
	c.JSON(404, gin.H{"error": "Domain not found"})
}
