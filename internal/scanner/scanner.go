package scanner

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"subtake/internal/config"
	"subtake/internal/fingerprints"
	"subtake/internal/httpclient"
)

// Result represents the result of scanning a subdomain
type Result struct {
	Subdomain     string                 `json:"subdomain"`
	Vulnerable    bool                   `json:"vulnerable"`
	Status        string                 `json:"status"`
	Evidence      []Evidence             `json:"evidence,omitempty"`
	Error         string                 `json:"error,omitempty"`
	HTTPResponse  *HTTPResponse          `json:"http_response,omitempty"`
	HTTPSResponse *HTTPResponse          `json:"https_response,omitempty"`
	ScanTime      time.Time              `json:"scan_time"`
}

// Evidence represents evidence of a vulnerability
type Evidence struct {
	Service   string `json:"service"`
	Pattern   string `json:"pattern"`
	Notes     string `json:"notes"`
	Snippet   string `json:"snippet"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Error      string            `json:"error,omitempty"`
}

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
func (s *Scanner) Scan(subdomains []string) []Result {
	results := make([]Result, len(subdomains))
	
	if s.config.Rate > 0 {
		// Use rate limiting
		s.scanWithRateLimit(subdomains, results)
	} else {
		// Use worker pool for concurrent scanning
		s.scanWithWorkers(subdomains, results)
	}
	
	return results
}

func (s *Scanner) scanWithRateLimit(subdomains []string, results []Result) {
	for i, subdomain := range subdomains {
		if s.rateLimiter != nil {
			<-s.rateLimiter.C
		}
		
		results[i] = s.scanSubdomain(subdomain)
	}
}

func (s *Scanner) scanWithWorkers(subdomains []string, results []Result) {
	const maxWorkers = 20
	subdomainChan := make(chan int, len(subdomains))
	resultChan := make(chan struct {
		index  int
		result Result
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
					result Result
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

func (s *Scanner) scanSubdomain(subdomain string) Result {
	result := Result{
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

func (s *Scanner) tryProtocol(subdomain, protocol string) *HTTPResponse {
	url := fmt.Sprintf("%s://%s", protocol, subdomain)
	
	resp := s.httpClient.Get(url)
	
	httpResp := &HTTPResponse{
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

func (s *Scanner) checkVulnerabilities(result Result, httpResp *HTTPResponse) Result {
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
			evidence := Evidence{
				Service: match.Service,
				Pattern: match.Pattern,
				Notes:   match.Notes,
				Snippet: s.extractSnippet(httpResp.Body, match.Pattern),
			}
			result.Evidence = append(result.Evidence, evidence)
		}
	} else {
		result.Status = "not vulnerable"
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

// Cleanup cleans up resources
func (s *Scanner) Cleanup() {
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
}
