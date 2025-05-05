# Build stage
FROM golang:1.22-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Fix potential line endings (for Windows users)
RUN apk add --no-cache dos2unix && \
    find . -type f -name "*.go" -exec dos2unix {} \;

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo -o emailserver ./cmd/server

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Set working directory
WORKDIR /app

# Create directories
RUN mkdir -p /var/lib/emailserver/emails /var/lib/emailserver/attachments /etc/emailserver

# Copy binary from builder stage
COPY --from=builder /app/emailserver /app/emailserver

# Copy configuration files
COPY config/config.yaml /etc/emailserver/config.yaml

# Copy database migrations
COPY db/migrations /app/db/migrations

# Set environment variables
ENV EMAILSERVER_CONFIG_FILE=/etc/emailserver/config.yaml

# Expose ports
EXPOSE 25 8080

# Run the application
CMD ["/app/emailserver", "--config", "/etc/emailserver/config.yaml"]
