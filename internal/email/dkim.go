package email

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/miekg/dns"
	"github.com/toorop/go-dkim"
)

// DKIMSigner handles signing outgoing emails with DKIM
type DKIMSigner struct {
	privateKey    *rsa.PrivateKey
	privateKeyPEM []byte // Store the PEM-encoded private key
	domain        string
	selector      string
}

// NewDKIMSigner creates a new DKIM signer
func NewDKIMSigner(domain, selector, keyPath string) (*DKIMSigner, error) {
	// Read private key file
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	// Parse private key
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &DKIMSigner{
		privateKey:    privateKey,
		privateKeyPEM: keyData, // Store the original PEM data
		domain:        domain,
		selector:      selector,
	}, nil
}

// SignMessage adds a DKIM signature to an email message
func (s *DKIMSigner) SignMessage(message []byte) ([]byte, error) {
	options := dkim.NewSigOptions()
	options.PrivateKey = s.privateKeyPEM // Use the PEM-encoded key
	options.Domain = s.domain
	options.Selector = s.selector
	options.SignatureExpireIn = 3600
	options.Headers = []string{"from", "to", "subject", "date"}
	options.AddSignatureTimestamp = true
	options.Canonicalization = "relaxed/relaxed"

	// The Sign function in go-dkim should modify the message and return an error
	err := dkim.Sign(&message, options)
	if err != nil {
		return nil, err
	}

	return message, nil
}

// VerifyDKIMSignature verifies a DKIM signature on an incoming email
func VerifyDKIMSignature(message []byte) (bool, error) {
	// The Verify function likely returns a status code
	status, err := dkim.Verify(&message)
	if err != nil {
		if strings.Contains(err.Error(), "no signature found") {
			return false, nil
		}
		return false, err
	}

	// Check if verification was successful
	if status == dkim.SUCCESS {
		return true, nil
	}

	return false, nil
}

// lookupPublicKey finds the DKIM public key for a domain
func lookupPublicKey(selector, domain string) ([]byte, error) {
	resolver := &dns.Client{}
	message := new(dns.Msg)

	record := selector + "._domainkey." + domain
	message.SetQuestion(dns.Fqdn(record), dns.TypeTXT)

	response, _, err := resolver.Exchange(message, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	if len(response.Answer) == 0 {
		return nil, fmt.Errorf("no DKIM record found for %s", record)
	}

	for _, answer := range response.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			dkimRecord := strings.Join(txt.Txt, "")

			// Extract public key from DKIM record
			parts := strings.Split(dkimRecord, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "p=") {
					publicKey := strings.TrimPrefix(part, "p=")
					decodedKey, err := base64.StdEncoding.DecodeString(publicKey)
					if err != nil {
						return nil, fmt.Errorf("failed to decode public key: %w", err)
					}
					return decodedKey, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no public key found in DKIM record for %s", record)
}
