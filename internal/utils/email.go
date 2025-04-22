package utils

import (
	"strings"
)

// GetDomainFromEmail extracts the domain part from an email address
func GetDomainFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
