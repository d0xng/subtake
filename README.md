# SubTake - Subdomain Takeover Detection Tool

SubTake is a powerful CLI tool written in Go for detecting subdomain takeover vulnerabilities. It scans subdomains against known hosting service fingerprints to identify potential takeover opportunities.

## Features

- **Comprehensive Fingerprint Database**: Built-in fingerprints for major hosting services (GitHub Pages, Vercel, Netlify, AWS S3, CloudFront, Fastly, Heroku, GitLab Pages, Azure, Firebase, Surge, and more)
- **Custom Fingerprints**: Support for custom fingerprint files in JSON/YAML format
- **Concurrent Scanning**: Worker pool with configurable concurrency for fast scanning
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming target servers
- **Multiple Input Methods**: Single subdomain or file with multiple subdomains
- **Flexible Output**: JSON output to file or stdout with colored terminal output
- **Robust Error Handling**: Retry logic, timeout handling, and detailed error reporting
- **TLS Support**: Configurable TLS verification with insecure mode option

## Installation

### Pre-built Binary

Download the latest release from the [releases page](https://github.com/yourusername/subtake/releases) and extract the binary to your PATH.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/subtake.git
cd subtake

# Build the binary
go build -o subtake .

# Or use the Makefile
make build
```

### Go Install

```bash
go install github.com/yourusername/subtake@latest
```

## Usage

### Basic Usage

```bash
# Scan a single subdomain
subtake scan example.com

# Scan multiple subdomains from a file
subtake scan -l subdomains.txt

# Save results to a file
subtake scan -l subdomains.txt -o results.json
```

### Advanced Usage

```bash
# Use custom fingerprints
subtake scan -l subdomains.txt --fingerprints custom-fingerprints.json

# Set custom user agent
subtake scan example.com --user-agent "MyBugBountyTool/1.0"

# Enable verbose output
subtake scan -l subdomains.txt -v

# Allow insecure TLS connections
subtake scan example.com --insecure

# Limit requests per second
subtake scan -l subdomains.txt --rate 2

# Set custom timeout and retries
subtake scan example.com --timeout 15 --timeout-retries 3
```

## Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-l, --list` | File containing subdomains (one per line) | - |
| `-o, --output` | Output file for results (JSON format) | stdout |
| `--fingerprints` | Custom fingerprints file (JSON/YAML) | built-in |
| `--user-agent` | User agent string for requests | "SubTake/1.0" |
| `--insecure` | Allow insecure TLS connections | false |
| `--rate` | Requests per second limit (0 = no limit) | 0 |
| `--timeout-retries` | Number of retries on timeout | 1 |
| `--timeout` | Request timeout in seconds | 10 |
| `-v, --verbose` | Verbose output for debugging | false |

## Input File Format

The input file should contain one subdomain per line:

```
subdomain1.example.com
subdomain2.example.com
subdomain3.example.com
```

Lines starting with `#` are treated as comments and ignored.

## Output Format

### Terminal Output

The tool provides colored terminal output:
- 🟢 **Green**: Vulnerable subdomains
- 🔴 **Red**: Not vulnerable subdomains
- 🟡 **Yellow**: Errors

### JSON Output

Results are output in JSON format with the following structure:

```json
[
  {
    "subdomain": "subdomain.example.com",
    "vulnerable": true,
    "status": "vulnerable",
    "evidence": [
      {
        "service": "GitHub Pages",
        "pattern": "There isn't a GitHub Pages site here.",
        "notes": "Indicates a CNAME pointing to GitHub Pages without content",
        "snippet": "...There isn't a GitHub Pages site here..."
      }
    ],
    "http_response": {
      "url": "http://subdomain.example.com",
      "status_code": 404,
      "headers": {
        "Server": "GitHub.com",
        "Content-Type": "text/html"
      },
      "body": "There isn't a GitHub Pages site here."
    },
    "https_response": {
      "url": "https://subdomain.example.com",
      "status_code": 404,
      "headers": {
        "Server": "GitHub.com",
        "Content-Type": "text/html"
      },
      "body": "There isn't a GitHub Pages site here."
    },
    "scan_time": "2024-01-15T10:30:00Z"
  }
]
```

## Custom Fingerprints

You can create custom fingerprint files in JSON or YAML format:

### JSON Format

```json
{
  "fingerprints": [
    {
      "service": "Custom Service",
      "pattern": "Custom error message",
      "notes": "Description of the fingerprint",
      "regex": false
    },
    {
      "service": "Custom Service Regex",
      "pattern": "(?i)custom.*error.*pattern",
      "notes": "Regex pattern for custom service",
      "regex": true
    }
  ]
}
```

### YAML Format

```yaml
fingerprints:
  - service: "Custom Service"
    pattern: "Custom error message"
    notes: "Description of the fingerprint"
    regex: false
  - service: "Custom Service Regex"
    pattern: "(?i)custom.*error.*pattern"
    notes: "Regex pattern for custom service"
    regex: true
```

## Built-in Fingerprints

SubTake comes with fingerprints for the following services:

- **GitHub Pages**: "There isn't a GitHub Pages site here."
- **Vercel**: "Project not found", "There isn't a Vercel deployment here"
- **Netlify**: "No such site", "There isn't a site here"
- **AWS S3**: "NoSuchBucket", "The specified bucket does not exist"
- **CloudFront**: "The request could not be satisfied"
- **Fastly**: "Fastly error: unknown domain", "Fastly has an error"
- **Heroku**: "no such app", "There is no app configured at that hostname"
- **GitLab Pages**: "The page you were looking for doesn't exist"
- **Azure Blob Storage**: "The specified container does not exist"
- **Firebase Hosting**: "Project Not Found"
- **Surge**: "project not found"
- **Generic Patterns**: Various common error messages

## Examples

### Basic Scanning

```bash
# Scan a single subdomain
subtake scan test.example.com

# Scan from file
subtake scan -l subdomains.txt
```

### Advanced Scanning

```bash
# Scan with custom settings
subtake scan -l subdomains.txt \
  --user-agent "BugBountyTool/1.0" \
  --rate 5 \
  --timeout 15 \
  --timeout-retries 2 \
  -o results.json \
  -v
```

### Custom Fingerprints

```bash
# Use custom fingerprints
subtake scan -l subdomains.txt --fingerprints my-fingerprints.json
```

## Testing

Run the test suite:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test package
go test ./tests/...
```

## Development

### Project Structure

```
subtake/
├── cmd/                    # CLI commands
│   ├── root.go            # Root command
│   └── scan.go            # Scan command
├── internal/              # Internal packages
│   ├── config/           # Configuration
│   ├── fingerprints/     # Fingerprint system
│   ├── httpclient/       # HTTP client
│   ├── output/           # Output formatting
│   └── scanner/          # Scanner logic
├── tests/                # Test files
├── fingerprints/         # Default fingerprints
├── main.go              # Main entry point
├── go.mod              # Go module file
└── README.md           # This file
```

### Building

```bash
# Build for current platform
go build -o subtake .

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o subtake-linux .

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o subtake.exe .

# Build for macOS
GOOS=darwin GOARCH=amd64 go build -o subtake-macos .
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and authorized testing purposes only. Only use it on systems you own or have explicit permission to test. The authors are not responsible for any misuse of this tool.

## Acknowledgments

- Inspired by various subdomain takeover detection tools
- Built with Go for performance and cross-platform compatibility
- Uses comprehensive fingerprint database for accurate detection
