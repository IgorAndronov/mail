package email

import (
	"github.com/yourusername/emailserver/internal/utils"
	"net"
	"sort"
	"strings"

	"github.com/yourusername/emailserver/internal/config"
	"gopkg.in/gomail.v2"
)

// OutboundService handles sending emails to external domains
type OutboundService struct {
	config     config.Config
	ownDomains []string
}

// MXRecord represents a mail exchange record with its priority
type MXRecord struct {
	Host     string
	Priority uint16
}

// NewOutboundService creates a new outbound email service
func NewOutboundService(config config.Config, ownDomains []string) *OutboundService {
	// If no domains are provided, default to the main domain
	if len(ownDomains) == 0 {
		ownDomains = []string{config.Domain}
	}

	return &OutboundService{
		config:     config,
		ownDomains: ownDomains,
	}
}

// SendEmail sends an email to an external recipient
func (s *OutboundService) SendEmail(from, to, subject, body string, isHTML bool) error {
	// Create a new message
	m := gomail.NewMessage()

	// Set headers
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)

	// Set content
	if isHTML {
		m.SetBody("text/html", body)
	} else {
		m.SetBody("text/plain", body)
	}

	// Get recipient domain
	domain := utils.GetDomainFromEmail(to)

	// Check if recipient domain is one of our own domains
	if s.isOwnDomain(domain) {
		// If it's our domain, send directly to our SMTP server
		dialer := gomail.NewDialer(s.config.SMTPHost, s.config.SMTPPort, "", "")
		dialer.SSL = false
		dialer.Auth = nil

		return dialer.DialAndSend(m)
	}

	// If it's an external domain, look up MX records
	return s.sendToExternalDomain(m, domain)
}

// SendEmailWithAttachments sends an email with attachments
func (s *OutboundService) SendEmailWithAttachments(from, to, subject, body string, isHTML bool, attachments []struct {
	Path        string
	Name        string
	ContentType string
}) error {
	// Create a new message
	m := gomail.NewMessage()

	// Set headers
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)

	// Set content
	if isHTML {
		m.SetBody("text/html", body)
	} else {
		m.SetBody("text/plain", body)
	}

	// Add attachments
	for _, attachment := range attachments {
		m.Attach(attachment.Path, gomail.Rename(attachment.Name))
	}

	// Get recipient domain
	domain := utils.GetDomainFromEmail(to)

	// Check if recipient domain is one of our own domains
	if s.isOwnDomain(domain) {
		// If it's our domain, send directly to our SMTP server
		dialer := gomail.NewDialer(s.config.SMTPHost, s.config.SMTPPort, "", "")
		dialer.SSL = false
		dialer.Auth = nil

		return dialer.DialAndSend(m)
	}

	// If it's an external domain, look up MX records
	return s.sendToExternalDomain(m, domain)
}

// sendToExternalDomain sends an email to an external domain using MX lookup
func (s *OutboundService) sendToExternalDomain(m *gomail.Message, domain string) error {
	// Lookup MX records
	mxRecords, err := lookupMXRecords(domain)
	if err != nil {
		return err
	}

	// Try each MX server in order of priority
	var lastError error
	for _, mx := range mxRecords {
		dialer := gomail.NewDialer(mx.Host, 25, "", "")
		dialer.SSL = false
		dialer.Auth = nil

		err := dialer.DialAndSend(m)
		if err == nil {
			return nil
		}
		lastError = err
	}

	// If all MX servers failed, return the last error
	if lastError != nil {
		return lastError
	}

	// Fall back to our own SMTP server if no MX records found
	dialer := gomail.NewDialer(s.config.SMTPHost, s.config.SMTPPort, "", "")
	dialer.SSL = false
	dialer.Auth = nil

	return dialer.DialAndSend(m)
}

// isOwnDomain checks if a domain is one of our own domains
func (s *OutboundService) isOwnDomain(domain string) bool {
	for _, ownDomain := range s.ownDomains {
		if strings.EqualFold(domain, ownDomain) {
			return true
		}
	}
	return false
}

// lookupMXRecords finds and sorts MX records for a domain
func lookupMXRecords(domain string) ([]MXRecord, error) {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		return nil, err
	}

	records := make([]MXRecord, len(mxs))
	for i, mx := range mxs {
		records[i] = MXRecord{
			Host:     mx.Host,
			Priority: mx.Pref,
		}
	}

	// Sort by priority (lower value = higher priority)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Priority < records[j].Priority
	})

	return records, nil
}

// IsExternalEmail checks if an email address is external (not belonging to our domains)
func (s *OutboundService) IsExternalEmail(email string) bool {
	domain := utils.GetDomainFromEmail(email)
	return !s.isOwnDomain(domain)
}

// IsExternalDomain checks if a domain is external to our server
func IsExternalEmail(email string, domain string) bool {
	return !strings.HasSuffix(email, "@"+domain)
}
