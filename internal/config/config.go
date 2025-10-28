package config

import "time"

// Config holds the configuration for the scanner
type Config struct {
	UserAgent      string
	Insecure       bool
	Rate           int
	TimeoutRetries int
	Timeout        time.Duration
	Verbose        bool
}
