package app

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/yourusername/emailserver/internal/config"
	"github.com/yourusername/emailserver/internal/db"
	"github.com/yourusername/emailserver/internal/models"
	"github.com/yourusername/emailserver/internal/smtpserver"
)

/* ------------------------------------------------------------------
   App struct — runtime container
-------------------------------------------------------------------*/

type App struct {
	// configuration & infrastructure
	cfg        config.Config
	db         *sqlx.DB
	smtpServer *smtp.Server
	webRouter  *gin.Engine

	// cached permission matrix
	allowedSenders map[string]map[string]bool // target → sender → bool
}

/* ------------------------------------------------------------------
   Public getters (required by smtpserver.AppAPI)
-------------------------------------------------------------------*/

func (a *App) GetDB() interface {
	Get(any, string, ...any) error
	Select(any, string, ...any) error
	Exec(string, ...any) (sql.Result, error)
} {
	return a.db
}
func (a *App) GetConfig() config.Config { return a.cfg }

/* ------------------------------------------------------------------
   Methods used by other layers
-------------------------------------------------------------------*/

func (a *App) SetWebRouter(r *gin.Engine) { a.webRouter = r }

func (a *App) AppendTrustedDomain(d string) {
	a.cfg.TrustedDomains = append(a.cfg.TrustedDomains, d)
}
func (a *App) RemoveTrustedDomain(d string) bool {
	for i, v := range a.cfg.TrustedDomains {
		if v == d {
			a.cfg.TrustedDomains = append(a.cfg.TrustedDomains[:i], a.cfg.TrustedDomains[i+1:]...)
			return true
		}
	}
	return false
}

/* permission helpers for smtpserver.Session */
func (a *App) IsEmailAllowed(from, to string) bool {
	return a.allowedSenders[to][from]
}
func (a *App) AddAllowedSender(target, sender string) {
	if a.allowedSenders[target] == nil {
		a.allowedSenders[target] = map[string]bool{}
	}
	a.allowedSenders[target][sender] = true
}

/* JWT helper for login handler */
func (a *App) GenerateJWT(u models.User) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":  u.ID,
		"email":    u.Email,
		"is_admin": u.IsAdmin,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	return t.SignedString([]byte(a.cfg.JWTSecret))
}

/* ------------------------------------------------------------------
   Init / Run / Close lifecycle
-------------------------------------------------------------------*/

func (a *App) Init() error {
	/* 1. configuration */
	c, err := config.Load()
	if err != nil {
		return err
	}
	a.cfg = c

	/* 2. database */
	dsn := db.DSN(c.DB.Host, c.DB.Port, c.DB.User, c.DB.Password, c.DB.DBName, c.DB.SSLMode)
	a.db, err = db.Connect(dsn)
	if err != nil {
		return err
	}

	/* 3. allowed senders cache */
	a.loadAllowedSenders()

	/* 4. SMTP server */
	a.initSMTP()
	return nil
}

func (a *App) Run() error {
	go func() {
		log.Printf("SMTP listening on %s", a.smtpServer.Addr)
		if err := a.smtpServer.ListenAndServe(); err != nil {
			log.Fatalf("smtp: %v", err)
		}
	}()
	return nil
}

func (a *App) Close() error {
	_ = a.smtpServer.Close()
	// Gin has no explicit shutdown here (router runs in main goroutine)
	return nil
}

/* ------------------------------------------------------------------
   internal helpers
-------------------------------------------------------------------*/

func (a *App) loadAllowedSenders() {
	a.allowedSenders = map[string]map[string]bool{}
	var prs []models.PermissionRequest
	err := a.db.Select(&prs,
		`SELECT * FROM permission_requests WHERE approved_at IS NOT NULL AND expires_at > NOW()`)
	if err != nil {
		log.Printf("load permission_requests: %v", err)
		return
	}
	for _, pr := range prs {
		if a.allowedSenders[pr.TargetMailbox] == nil {
			a.allowedSenders[pr.TargetMailbox] = map[string]bool{}
		}
		a.allowedSenders[pr.TargetMailbox][pr.RequestorEmail] = true
	}
}

func (a *App) initSMTP() {
	be := smtpserver.NewBackend(a)
	s := smtp.NewServer(be)
	s.Addr = fmt.Sprintf("%s:%d", a.cfg.SMTPHost, a.cfg.SMTPPort)
	s.Domain = a.cfg.Domain
	s.ReadTimeout, s.WriteTimeout = 10*time.Second, 10*time.Second
	s.MaxMessageBytes, s.MaxRecipients = 1<<20, 50
	s.AllowInsecureAuth = true

	if a.cfg.CertFile != "" && a.cfg.KeyFile != "" {
		if cert, err := tls.LoadX509KeyPair(a.cfg.CertFile, a.cfg.KeyFile); err == nil {
			s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		} else {
			log.Printf("TLS disabled: %v", err)
		}
	}

	a.smtpServer = s
}
