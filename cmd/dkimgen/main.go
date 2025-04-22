package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	domain := flag.String("domain", "", "Domain for DKIM key")
	selector := flag.String("selector", "mail", "DKIM selector")
	outputDir := flag.String("output", ".", "Output directory")
	flag.Parse()

	if *domain == "" {
		log.Fatal("Domain is required")
	}

	// Generate a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// Save private key to file
	privateKeyFile, err := os.Create(fmt.Sprintf("%s/private.key", *outputDir))
	if err != nil {
		log.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		log.Fatalf("Failed to encode private key: %v", err)
	}

	// Extract public key
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create TXT record for DNS
	fmt.Printf("Add this TXT record to your DNS:\n")
	fmt.Printf("%s._domainkey.%s IN TXT \"v=DKIM1;k=rsa;p=%s\"\n",
		*selector, *domain, formatDNSTXTRecord(publicKeyBytes))
}

func formatDNSTXTRecord(publicKeyBytes []byte) string {
	// Format public key for DNS TXT record
	return "your_formatted_public_key"
}
