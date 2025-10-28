package httpclient

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"subtake/internal/config"
)

// Client wraps the HTTP client with custom configuration
type Client struct {
	httpClient *http.Client
	config     *config.Config
}

// Response holds the HTTP response data
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       string
	Error      error
}

// New creates a new HTTP client with the given configuration
func New(cfg *config.Config) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow up to 10 redirects
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Client{
		httpClient: client,
		config:     cfg,
	}
}

// Get performs an HTTP GET request with retries
func (c *Client) Get(url string) *Response {
	var lastErr error

	for attempt := 0; attempt <= c.config.TimeoutRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		resp, err := c.doRequest(url)
		if err != nil {
			lastErr = err
			continue
		}

		return resp
	}

	return &Response{
		Error: fmt.Errorf("request failed after %d attempts: %w", c.config.TimeoutRetries+1, lastErr),
	}
}

func (c *Client) doRequest(url string) (*Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body (limit to first and last 8KB as specified)
	body, err := c.readBody(resp.Body)
	if err != nil {
		return nil, err
	}

	// Convert headers to map
	headers := make(map[string]string)
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       body,
	}, nil
}

func (c *Client) readBody(body io.ReadCloser) (string, error) {
	// Read the entire body first
	allData, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	// Check if content is gzip compressed
	var reader io.Reader = strings.NewReader(string(allData))
	if len(allData) >= 2 && allData[0] == 0x1f && allData[1] == 0x8b {
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			// If gzip decompression fails, return original data
			return string(allData), nil
		}
		defer gzReader.Close()

		decompressed, err := io.ReadAll(gzReader)
		if err != nil {
			// If decompression fails, return original data
			return string(allData), nil
		}
		allData = decompressed
	}

	// If body is small enough, return it all
	if len(allData) <= 16384 { // 16KB total (8KB + 8KB)
		return string(allData), nil
	}

	// Otherwise, take first 8KB + last 8KB
	first8KB := string(allData[:8192])
	last8KB := string(allData[len(allData)-8192:])

	return first8KB + "\n... [truncated] ...\n" + last8KB, nil
}
