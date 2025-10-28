package types

import "time"

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
	Service string `json:"service"`
	Pattern string `json:"pattern"`
	Notes   string `json:"notes"`
	Snippet string `json:"snippet"`
}

// HTTPResponse represents an HTTP response
type HTTPResponse struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Error      string            `json:"error,omitempty"`
}
