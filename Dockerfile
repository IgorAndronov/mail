# Build stage
FROM golang:1.21-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod ./
# Create empty go.sum if it doesn't exist yet
RUN touch go.sum
COPY go.sum ./

# Initialize Go modules
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Fix potential line ending issues (in case of Windows)
RUN apk add --no-cache dos2unix \
    && find . -type f -name "*.go" -exec dos2unix {} \;

# Build the application with detailed output
RUN go build -v -o emailserver .

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Set working directory
WORKDIR /app

# Create directories
RUN mkdir -p /var/lib/emailserver/emails /etc/emailserver

# Copy binary from builder stage
COPY --from=builder /app/emailserver /app/emailserver

# Copy configuration files
COPY config.yaml /etc/emailserver/config.yaml

# Set environment variables
ENV EMAILSERVER_CONFIG_FILE=/etc/emailserver/config.yaml

# Expose ports
EXPOSE 25 8080

# Run the application
CMD ["/app/emailserver", "--config", "/etc/emailserver/config.yaml"]