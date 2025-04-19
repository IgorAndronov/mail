.PHONY: build run clean docker-build docker-run docker-stop docker-clean migrate test help

# Default target
all: build

# Build the application
build:
	@echo "Building emailserver..."
	go build -o bin/emailserver

# Run the application directly (not in container)
run: build
	@echo "Running emailserver..."
	./bin/emailserver

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -f bin/emailserver
	go clean

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker-compose build

# Run Docker containers
docker-run:
	@echo "Starting Docker containers..."
	docker-compose up -d

# Stop Docker containers
docker-stop:
	@echo "Stopping Docker containers..."
	docker-compose down

# Clean Docker resources
docker-clean:
	@echo "Cleaning Docker resources..."
	docker-compose down -v

# Run database migrations manually
migrate:
	@echo "Running database migrations..."
	docker-compose run --rm liquibase

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  build           - Build the application"
	@echo "  run             - Run the application directly"
	@echo "  clean           - Clean build artifacts"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Start Docker containers"
	@echo "  docker-stop     - Stop Docker containers"
	@echo "  docker-clean    - Clean Docker resources"
	@echo "  migrate         - Run database migrations"
	@echo "  test            - Run tests"
	@echo "  help            - Show this help"