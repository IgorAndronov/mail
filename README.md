Email Server
A modern email server written in Go that supports all modern mail clients, with domain-based security and user registration features.

Features
SMTP server with authentication
Web API for managing mailboxes and emails
Support for trusted domains
User registration and management
Email permission request system
Docker and Docker Compose support
Liquibase database migrations
Requirements
For local development:
Go 1.21 or higher
PostgreSQL
Liquibase (for database migrations)
For Docker deployment:
Docker
Docker Compose
Configuration
Configuration is handled through a YAML file (config.yaml) and can be overridden with environment variables:

yaml
# SMTP Server Configuration
smtp:
  host: "0.0.0.0"
  port: 25

# Web API Configuration
web:
  host: "0.0.0.0"
  port: 8080

# Domain Configuration
domain: "example.com"

# Database Configuration
db:
  host: "postgres"
  port: 5432
  user: "emailserver"
  password: "securepassword"
  name: "emailserver"
  sslmode: "disable"

# Trusted Domains
trusted_domains:
  - "trusted1.com"
  - "trusted2.com"

# JWT Secret for authentication
jwt_secret: "your-very-secure-jwt-secret-key"

# TLS Configuration (optional)
tls:
  cert_file: "/etc/certs/server.crt"
  key_file: "/etc/certs/server.key"

# Email Storage Path
email_storage_path: "/var/lib/emailserver/emails"
Installation
Using Docker (recommended)
Clone the repository:
bash
git clone https://github.com/yourusername/emailserver.git
cd emailserver
Configure the server by editing config.yaml
Build and start the containers:
bash
make docker-build
make docker-run
Manual Installation
Clone the repository:
bash
git clone https://github.com/yourusername/emailserver.git
cd emailserver
Configure the server by editing config.yaml
Run database migrations:
bash
cd db
liquibase --changelog-file=db.xml --url=jdbc:postgresql://localhost:5432/emailserver --username=emailserver --password=securepassword update
Build and run the server:
bash
make build
make run
Usage
Default Admin User
A default admin user is created during the initial database setup:

Email: admin@example.com
Password: admin123
⚠️ Important: Change the default admin password immediately in production!

API Endpoints
Public Endpoints
POST /api/register - Register a new user
POST /api/login - Login and get JWT token
GET /api/confirm-permission/:token - Confirm permission request
Protected Endpoints (requires JWT token)
POST /api/mailboxes - Create a new mailbox
GET /api/mailboxes - List user's mailboxes
GET /api/emails/:mailboxId - List emails in a mailbox
GET /api/emails/:mailboxId/:emailId - Get specific email
DELETE /api/emails/:mailboxId/:emailId - Delete email
POST /api/request-permission - Request permission to send emails
Admin Endpoints (requires admin JWT token)
GET /api/admin/users - List all users
POST /api/admin/trusted-domains - Add trusted domain
DELETE /api/admin/trusted-domains/:domain - Remove trusted domain
Sending Emails
Emails can be sent to the server using any SMTP client using the following rules:

The sender must be from a trusted domain, or
The sender must be a registered user with an account on the server, or
The sender must have explicit permission to send to the recipient
Requesting Permissions
To request permission to send emails to a specific mailbox:

Use the API endpoint POST /api/request-permission with the target mailbox
The mailbox owner will receive a confirmation email with a link
Once approved, emails from the requester will be accepted
Development
Directory Structure
.
├── db/             # Database migrations
├── config.yaml     # Configuration file
├── docker-compose.yml
├── Dockerfile
├── go.mod
├── go.sum
├── main.go         # Main application code
├── Makefile        # Build and run commands
└── README.md
Makefile Commands
make build - Build the application
make run - Run the application directly
make clean - Clean build artifacts
make docker-build - Build Docker image
make docker-run - Start Docker containers
make docker-stop - Stop Docker containers
make docker-clean - Clean Docker resources
make migrate - Run database migrations
make test - Run tests
make help - Show available commands
Security Considerations
Change the default admin password immediately
Use a strong JWT secret in production
Use TLS in production by providing certificate and key files
Regularly review and update trusted domains
Store the database password securely
Consider using a reverse proxy like Nginx for TLS termination
License
This project is licensed under the MIT License - see the LICENSE file for details.

