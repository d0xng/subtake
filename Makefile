# SubTake Makefile

# Variables
BINARY_NAME=subtake
VERSION=1.0.0
BUILD_DIR=build
GO_VERSION=1.21

# Default target
.PHONY: all
all: clean build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME) .

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .

# No tests needed for this tool

# Lint the code
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, installing..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		golangci-lint run; \
	fi

# Format the code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet the code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run the application
.PHONY: run
run: build
	@echo "Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME)

# Run with example subdomain
.PHONY: run-example
run-example: build
	@echo "Running $(BINARY_NAME) with example subdomain..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan example.com

# Create example subdomains file
.PHONY: example-file
example-file:
	@echo "Creating example subdomains file..."
	@echo "# Example subdomains file" > example-subdomains.txt
	@echo "test.example.com" >> example-subdomains.txt
	@echo "subdomain.example.com" >> example-subdomains.txt
	@echo "api.example.com" >> example-subdomains.txt
	@echo "Example file created: example-subdomains.txt"

# Run with example file
.PHONY: run-file
run-file: build example-file
	@echo "Running $(BINARY_NAME) with example file..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan -l example-subdomains.txt

# Install the binary to GOPATH/bin
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	go install .

# Uninstall the binary
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	go clean -i

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  vet            - Vet code"
	@echo "  clean          - Clean build artifacts"
	@echo "  deps           - Install dependencies"
	@echo "  run            - Run the application"
	@echo "  run-example    - Run with example subdomain"
	@echo "  run-file       - Run with example file"
	@echo "  install        - Install binary to GOPATH/bin"
	@echo "  uninstall      - Uninstall binary"
	@echo "  help           - Show this help"

# Development targets
.PHONY: dev
dev: deps fmt vet build

# CI/CD targets
.PHONY: ci
ci: deps fmt vet lint build

# Release targets
.PHONY: release
release: clean build-all
	@echo "Release build complete. Binaries are in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

# Docker targets (if needed)
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .

.PHONY: docker-run
docker-run: docker-build
	@echo "Running Docker container..."
	docker run --rm $(BINARY_NAME):$(VERSION)
