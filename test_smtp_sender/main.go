package main

import (
	"fmt"
	"log"
	"net/smtp"
)

func main() {
	// SMTP server configuration.
	smtpHost := "localhost"
	smtpPort := "25"

	// Authentication.
	username := "external@otherdomain.com"
	password := "externalpass123"

	// Message.
	from := "external@otherdomain.com"
	to := []string{"test@example.com"}
	subject := "Test Email from Go"
	body := "This is a test email sent using Go!"

	// Email format.
	msg := []byte("To: test@example.com\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	// Auth.
	auth := smtp.PlainAuth("", username, password, smtpHost)

	// Sending email.
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Email sent successfully")
}
