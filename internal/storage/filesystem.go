package storage

import (
	"encoding/base64"
	"fmt"
	"github.com/yourusername/emailserver/internal/models"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
)

// FileStorage provides file storage operations
type FileStorage struct {
	basePath string
}

// NewFileStorage creates a new file storage instance
func NewFileStorage(basePath string) (*FileStorage, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Create attachments directory
	attachmentsDir := filepath.Join(basePath, "attachments")
	if err := os.MkdirAll(attachmentsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create attachments directory: %w", err)
	}

	return &FileStorage{basePath: basePath}, nil
}

// SaveEmail saves an email to a file
func (f *FileStorage) SaveEmail(emailID string, data []byte) error {
	emailPath := filepath.Join(f.basePath, emailID+".eml")
	return os.WriteFile(emailPath, data, 0644)
}

// GetEmail retrieves an email from a file
func (f *FileStorage) GetEmail(emailID string) ([]byte, error) {
	emailPath := filepath.Join(f.basePath, emailID+".eml")
	return os.ReadFile(emailPath)
}

// DeleteEmail deletes an email file
func (f *FileStorage) DeleteEmail(emailID string) error {
	emailPath := filepath.Join(f.basePath, emailID+".eml")
	return os.Remove(emailPath)
}

// SaveAttachment saves an attachment file
func (f *FileStorage) SaveAttachment(emailID string, filename string, data []byte) (string, error) {
	// Create directory for attachments
	attachmentsDir := filepath.Join(f.basePath, "attachments", emailID)
	if err := os.MkdirAll(attachmentsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create attachment directory: %w", err)
	}

	// Sanitize filename
	sanitizedFilename := filepath.Base(filename)
	attachmentPath := filepath.Join(attachmentsDir, sanitizedFilename)

	// Save file
	if err := os.WriteFile(attachmentPath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to save attachment: %w", err)
	}

	return attachmentPath, nil
}

// ExtractAttachments parses an email and extracts attachments
func (f *FileStorage) ExtractAttachments(emailData []byte, emailID string) ([]models.AttachmentInfo, error) {
	// Parse the email
	msg, err := mail.ReadMessage(strings.NewReader(string(emailData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	// Check if email has attachments
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		// No content type, assume no attachments
		return nil, nil
	}

	// Create attachments directory
	attachmentsDir := filepath.Join(f.basePath, "attachments", emailID)
	if err := os.MkdirAll(attachmentsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create attachments directory: %w", err)
	}

	// Check if this is a multipart message
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse content type: %w", err)
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		// Not a multipart message, no attachments
		return nil, nil
	}

	// Process multipart message
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("no multipart boundary found")
	}

	reader := multipart.NewReader(msg.Body, boundary)
	var attachments []models.AttachmentInfo

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return attachments, fmt.Errorf("error reading multipart: %w", err)
		}

		// Check if this part is an attachment
		disposition := part.Header.Get("Content-Disposition")
		if disposition == "" {
			continue
		}

		_, dispositionParams, err := mime.ParseMediaType(disposition)
		if err != nil {
			continue
		}

		filename := dispositionParams["filename"]
		if filename == "" {
			// Not an attachment or filename not specified
			continue
		}

		// Get content type of the part
		partContentType := part.Header.Get("Content-Type")
		if partContentType == "" {
			partContentType = "application/octet-stream"
		}

		// Create a file to save the attachment
		attachmentPath := filepath.Join(attachmentsDir, filename)
		file, err := os.Create(attachmentPath)
		if err != nil {
			continue
		}

		// Check if content is base64 encoded
		encoding := part.Header.Get("Content-Transfer-Encoding")
		var size int64

		if strings.EqualFold(encoding, "base64") {
			decoder := base64.NewDecoder(base64.StdEncoding, part)
			size, err = io.Copy(file, decoder)
		} else {
			size, err = io.Copy(file, part)
		}

		file.Close()

		if err != nil {
			os.Remove(attachmentPath)
			continue
		}

		// Add to attachments list
		attachments = append(attachments, models.AttachmentInfo{
			FileName:    filename,
			ContentType: partContentType,
			Size:        size,
			Path:        attachmentPath,
		})
	}

	return attachments, nil
}

// CreateMultipartMessage creates a multipart message with attachments
func (f *FileStorage) CreateMultipartMessage(body string, isHTML bool, attachments []models.AttachmentInfo, boundary string) (string, error) {
	multipartMessage := "MIME-Version: 1.0\r\n"

	if isHTML {
		multipartMessage += "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n"
		multipartMessage += "--" + boundary + "\r\n"
		multipartMessage += "Content-Type: text/html; charset=UTF-8\r\n\r\n"
	} else {
		multipartMessage += "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n"
		multipartMessage += "--" + boundary + "\r\n"
		multipartMessage += "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
	}

	multipartMessage += body + "\r\n\r\n"

	// Add each attachment
	for _, attachment := range attachments {
		fileData, err := os.ReadFile(attachment.Path)
		if err != nil {
			continue
		}

		multipartMessage += "--" + boundary + "\r\n"
		multipartMessage += "Content-Type: " + attachment.ContentType + "\r\n"
		multipartMessage += "Content-Disposition: attachment; filename=\"" + attachment.FileName + "\"\r\n"
		multipartMessage += "Content-Transfer-Encoding: base64\r\n\r\n"
		multipartMessage += base64.StdEncoding.EncodeToString(fileData) + "\r\n"
	}

	multipartMessage += "--" + boundary + "--\r\n"

	return multipartMessage, nil
}

// DeleteAttachment deletes an attachment file
func (f *FileStorage) DeleteAttachment(path string) error {
	return os.Remove(path)
}

// DeleteAttachmentsForEmail deletes all attachments for an email
func (f *FileStorage) DeleteAttachmentsForEmail(emailID string) error {
	attachmentsDir := filepath.Join(f.basePath, "attachments", emailID)
	return os.RemoveAll(attachmentsDir)
}
