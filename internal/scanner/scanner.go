package scanner

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"subtake/internal/config"
	"subtake/internal/fingerprints"
	"subtake/internal/httpclient"
	"subtake/internal/types"
)

// Scanner handles the scanning of subdomains
type Scanner struct {
	config       *config.Config
	fingerprints *fingerprints.Fingerprints
	httpClient   *httpclient.Client
	rateLimiter  *time.Ticker
}

// New creates a new scanner
func New(cfg *config.Config, fp *fingerprints.Fingerprints) *Scanner {
	client := httpclient.New(cfg)

	var rateLimiter *time.Ticker
	if cfg.Rate > 0 {
		interval := time.Second / time.Duration(cfg.Rate)
		rateLimiter = time.NewTicker(interval)
	}

	return &Scanner{
		config:       cfg,
		fingerprints: fp,
		httpClient:   client,
		rateLimiter:  rateLimiter,
	}
}

// Scan scans a list of subdomains
func (s *Scanner) Scan(subdomains []string) []types.Result {
	results := make([]types.Result, len(subdomains))

	if s.config.Rate > 0 {
		// Use rate limiting
		s.scanWithRateLimit(subdomains, results)
	} else {
		// Use worker pool for concurrent scanning
		s.scanWithWorkers(subdomains, results)
	}

	return results
}

// ScanWithRealtimeOutput scans subdomains and outputs results in real-time
func (s *Scanner) ScanWithRealtimeOutput(subdomains []string) []types.Result {
	results := make([]types.Result, len(subdomains))

	if s.config.Rate > 0 {
		// Use rate limiting with real-time output
		s.scanWithRateLimitRealtime(subdomains, results)
	} else {
		// Use worker pool with real-time output
		s.scanWithWorkersRealtime(subdomains, results)
	}

	return results
}

func (s *Scanner) scanWithRateLimit(subdomains []string, results []types.Result) {
	for i, subdomain := range subdomains {
		if s.rateLimiter != nil {
			<-s.rateLimiter.C
		}

		results[i] = s.scanSubdomain(subdomain)
	}
}

func (s *Scanner) scanWithRateLimitRealtime(subdomains []string, results []types.Result) {
	for i, subdomain := range subdomains {
		if s.rateLimiter != nil {
			<-s.rateLimiter.C
		}

		results[i] = s.scanSubdomain(subdomain)
		// Print result immediately
		s.printResult(results[i])
	}
}

func (s *Scanner) scanWithWorkers(subdomains []string, results []types.Result) {
	const maxWorkers = 20
	subdomainChan := make(chan int, len(subdomains))
	resultChan := make(chan struct {
		index  int
		result types.Result
	}, len(subdomains))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range subdomainChan {
				result := s.scanSubdomain(subdomains[index])
				resultChan <- struct {
					index  int
					result types.Result
				}{index, result}
			}
		}()
	}

	// Send work
	for i := range subdomains {
		subdomainChan <- i
	}
	close(subdomainChan)

	// Wait for completion
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results[result.index] = result.result
	}
}

func (s *Scanner) scanWithWorkersRealtime(subdomains []string, results []types.Result) {
	const maxWorkers = 20
	subdomainChan := make(chan int, len(subdomains))
	resultChan := make(chan struct {
		index  int
		result types.Result
	}, len(subdomains))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range subdomainChan {
				result := s.scanSubdomain(subdomains[index])
				resultChan <- struct {
					index  int
					result types.Result
				}{index, result}
			}
		}()
	}

	// Send work
	for i := range subdomains {
		subdomainChan <- i
	}
	close(subdomainChan)

	// Wait for completion
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results and print immediately
	for result := range resultChan {
		results[result.index] = result.result
		// Print result immediately
		s.printResult(result.result)
	}
}

func (s *Scanner) scanSubdomain(subdomain string) types.Result {
	result := types.Result{
		Subdomain: subdomain,
		ScanTime:  time.Now(),
	}

	// Try HTTPS first, then HTTP
	httpsResult := s.tryProtocol(subdomain, "https")
	httpResult := s.tryProtocol(subdomain, "http")

	result.HTTPSResponse = httpsResult
	result.HTTPResponse = httpResult

	// Check for vulnerabilities
	if httpsResult != nil && httpsResult.Error == "" {
		result = s.checkVulnerabilities(result, httpsResult)
	} else if httpResult != nil && httpResult.Error == "" {
		result = s.checkVulnerabilities(result, httpResult)
	} else {
		result.Status = "error"
		result.Error = "both HTTPS and HTTP requests failed"
		if httpsResult != nil && httpsResult.Error != "" {
			result.Error = httpsResult.Error
		} else if httpResult != nil && httpResult.Error != "" {
			result.Error = httpResult.Error
		}
	}

	return result
}

func (s *Scanner) tryProtocol(subdomain, protocol string) *types.HTTPResponse {
	url := fmt.Sprintf("%s://%s", protocol, subdomain)

	resp := s.httpClient.Get(url)

	httpResp := &types.HTTPResponse{
		URL:        url,
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	}

	if resp.Error != nil {
		httpResp.Error = resp.Error.Error()
	}

	return httpResp
}

func (s *Scanner) checkVulnerabilities(result types.Result, httpResp *types.HTTPResponse) types.Result {
	// Debug output in verbose mode
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "Checking %s - Status: %d, Body length: %d\n", result.Subdomain, httpResp.StatusCode, len(httpResp.Body))
		// Show first 1000 characters of body
		bodyPreview := httpResp.Body
		if len(bodyPreview) > 1000 {
			bodyPreview = bodyPreview[:1000] + "..."
		}
		fmt.Fprintf(os.Stderr, "Body content: %q\n", bodyPreview)
	}

	// Check fingerprints against response body
	matches, err := s.fingerprints.Match(httpResp.Body, httpResp.Headers)
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("fingerprint matching error: %v", err)
		return result
	}

	if len(matches) > 0 {
		result.Vulnerable = true
		result.Status = "vulnerable"

		// Create evidence for each match
		for _, match := range matches {
			evidence := types.Evidence{
				Service: match.Service,
				Pattern: match.Pattern,
				Notes:   match.Notes,
				Snippet: s.extractSnippet(httpResp.Body, match.Pattern),
			}
			result.Evidence = append(result.Evidence, evidence)
		}

		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "Found %d matches for %s\n", len(matches), result.Subdomain)
		}
	} else {
		result.Status = "not vulnerable"
		if s.config.Verbose {
			fmt.Fprintf(os.Stderr, "No matches found for %s\n", result.Subdomain)
		}
	}

	return result
}

func (s *Scanner) extractSnippet(body, pattern string) string {
	// Extract a snippet around the matched pattern
	bodyLower := strings.ToLower(body)
	patternLower := strings.ToLower(pattern)

	index := strings.Index(bodyLower, patternLower)
	if index == -1 {
		return ""
	}

	start := index - 100
	if start < 0 {
		start = 0
	}

	end := index + len(pattern) + 100
	if end > len(body) {
		end = len(body)
	}

	return body[start:end]
}

// printResult prints a single scan result with colors
func (s *Scanner) printResult(result types.Result) {
	// Color coding based on vulnerability status
	var color string
	var status string

	switch result.Status {
	case "vulnerable":
		color = "\033[32m" // Green
		status = "VULNERABLE"
	case "not vulnerable":
		color = "\033[31m" // Red
		status = "NOT VULNERABLE"
	case "error":
		color = "\033[33m" // Yellow
		status = "ERROR"
	default:
		color = "\033[34m" // Blue
		status = strings.ToUpper(result.Status)
	}

	// Print status and subdomain
	fmt.Printf("%s[%s]\033[0m %s", color, status, result.Subdomain)

	// Show details only for vulnerable subdomains
	if result.Vulnerable && len(result.Evidence) > 0 {
		fmt.Printf(" - %s", result.Evidence[0].Service)

		// Show the specific pattern that matched (truncated)
		if result.Evidence[0].Pattern != "" {
			pattern := result.Evidence[0].Pattern
			if len(pattern) > 50 {
				pattern = pattern[:47] + "..."
			}
			fmt.Printf(" (\"%s\")", pattern)
		}

		if len(result.Evidence) > 1 {
			fmt.Printf(" (+%d more)", len(result.Evidence)-1)
		}
	}

	// Show simplified error message for errors
	if result.Status == "error" && result.Error != "" {
		// Simplify error message
		errorMsg := result.Error
		if strings.Contains(errorMsg, "request failed after") {
			errorMsg = "request failed"
		} else if strings.Contains(errorMsg, "no such host") {
			errorMsg = "invalid domain"
		} else if strings.Contains(errorMsg, "timeout") {
			errorMsg = "timeout"
		} else if len(errorMsg) > 30 {
			errorMsg = errorMsg[:27] + "..."
		}
		fmt.Printf(" - %s", errorMsg)
	}

	fmt.Println()
}

// Cleanup cleans up resources
func (s *Scanner) Cleanup() {
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
}
