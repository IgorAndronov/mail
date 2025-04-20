package smtpserver

import (
	"database/sql" // ← add
	"github.com/emersion/go-smtp"

	"github.com/yourusername/emailserver/internal/config"
)

/* -------- AppAPI: Exec now returns sql.Result ------------------- */

type AppAPI interface {
	GetDB() interface {
		Get(dest interface{}, q string, args ...interface{}) error
		Select(dest interface{}, q string, args ...interface{}) error
		Exec(q string, args ...interface{}) (sql.Result, error) // ← fix
	}
	GetConfig() config.Config
	IsEmailAllowed(from, to string) bool
	AddAllowedSender(target, sender string)
}

/* Backend struct & NewBackend unchanged */
type Backend struct{ app AppAPI }

func NewBackend(a AppAPI) *Backend { return &Backend{app: a} }

func (b *Backend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return NewSession(b.app), nil
}
