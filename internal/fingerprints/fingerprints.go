package fingerprints

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Fingerprint represents a single fingerprint pattern
type Fingerprint struct {
	Service string `json:"service" yaml:"service"`
	Pattern string `json:"pattern" yaml:"pattern"`
	Notes   string `json:"notes" yaml:"notes"`
	Regex   bool   `json:"regex" yaml:"regex"`
}

// Fingerprints holds a collection of fingerprints
type Fingerprints struct {
	Fingerprints []Fingerprint `json:"fingerprints" yaml:"fingerprints"`
}

// Load loads fingerprints from default and custom files
func Load(customFile string) (*Fingerprints, error) {
	// Load default fingerprints
	defaultFp := GetDefaultFingerprints()
	
	if customFile == "" {
		return defaultFp, nil
	}

	// Load custom fingerprints
	customFp, err := loadFromFile(customFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom fingerprints: %w", err)
	}

	// Merge custom fingerprints with default ones
	merged := &Fingerprints{
		Fingerprints: append(defaultFp.Fingerprints, customFp.Fingerprints...),
	}

	return merged, nil
}

func loadFromFile(filename string) (*Fingerprints, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var fp Fingerprints
	
	// Try JSON first, then YAML
	if strings.HasSuffix(strings.ToLower(filename), ".json") {
		err = json.Unmarshal(data, &fp)
	} else {
		err = yaml.Unmarshal(data, &fp)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse fingerprints file: %w", err)
	}

	return &fp, nil
}

// Match checks if the given content matches any fingerprint
func (fp *Fingerprints) Match(content string, headers map[string]string) ([]Fingerprint, error) {
	var matches []Fingerprint
	
	for _, fingerprint := range fp.Fingerprints {
		matched, err := fingerprint.Match(content, headers)
		if err != nil {
			return nil, err
		}
		
		if matched {
			matches = append(matches, fingerprint)
		}
	}
	
	return matches, nil
}

// Match checks if the fingerprint matches the given content
func (f *Fingerprint) Match(content string, headers map[string]string) (bool, error) {
	if f.Regex {
		re, err := regexp.Compile(f.Pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex pattern %s: %w", f.Pattern, err)
		}
		return re.MatchString(content), nil
	}
	
	// Case-insensitive string matching
	return strings.Contains(strings.ToLower(content), strings.ToLower(f.Pattern)), nil
}

// GetDefaultFingerprints returns the built-in fingerprints
func GetDefaultFingerprints() *Fingerprints {
	return &Fingerprints{
		Fingerprints: []Fingerprint{
			// GitHub Pages
			{
				Service: "GitHub Pages",
				Pattern: "There isn't a GitHub Pages site here.",
				Notes:   "Indicates a CNAME pointing to GitHub Pages without content",
				Regex:   false,
			},
			{
				Service: "GitHub Pages",
				Pattern: "(?i)github pages.*not found|there isn't a github pages site",
				Notes:   "GitHub Pages error variations",
				Regex:   true,
			},
			
			// Vercel
			{
				Service: "Vercel",
				Pattern: "(?i)project not found|there isn't a vercel deployment here|no such host",
				Notes:   "Typical message when alias points to Vercel without deployment",
				Regex:   true,
			},
			
			// Netlify
			{
				Service: "Netlify",
				Pattern: "No such site",
				Notes:   "Netlify default page text",
				Regex:   false,
			},
			{
				Service: "Netlify",
				Pattern: "There isn't a site here",
				Notes:   "Netlify default page text variation",
				Regex:   false,
			},
			{
				Service: "Netlify",
				Pattern: "(?i)netlify.*not found|404.*netlify",
				Notes:   "Netlify error with reference in body",
				Regex:   true,
			},
			
			// AWS S3
			{
				Service: "AWS S3",
				Pattern: "NoSuchBucket",
				Notes:   "AWS S3 XML error for non-existent bucket",
				Regex:   false,
			},
			{
				Service: "AWS S3",
				Pattern: "The specified bucket does not exist",
				Notes:   "AWS S3 error message",
				Regex:   false,
			},
			{
				Service: "AWS S3",
				Pattern: "(?i)aws.*s3.*error|amazon.*s3.*not found",
				Notes:   "AWS S3 error variations",
				Regex:   true,
			},
			
			// CloudFront
			{
				Service: "CloudFront",
				Pattern: "The request could not be satisfied",
				Notes:   "CloudFront error message",
				Regex:   false,
			},
			{
				Service: "CloudFront",
				Pattern: "(?i)cloudfront.*error|aws.*cloudfront",
				Notes:   "CloudFront error variations",
				Regex:   true,
			},
			
			// Fastly
			{
				Service: "Fastly",
				Pattern: "Fastly error: unknown domain",
				Notes:   "Fastly error for unknown domain",
				Regex:   false,
			},
			{
				Service: "Fastly",
				Pattern: "Fastly error: unknown service",
				Notes:   "Fastly error for unknown service",
				Regex:   false,
			},
			{
				Service: "Fastly",
				Pattern: "Fastly has an error",
				Notes:   "Fastly generic error",
				Regex:   false,
			},
			
			// Heroku
			{
				Service: "Heroku",
				Pattern: "no such app",
				Notes:   "Heroku app not found",
				Regex:   false,
			},
			{
				Service: "Heroku",
				Pattern: "There is no app configured at that hostname",
				Notes:   "Heroku custom domain removed",
				Regex:   false,
			},
			{
				Service: "Heroku",
				Pattern: "(?i)heroku.*not found|heroku.*error",
				Notes:   "Heroku error variations",
				Regex:   true,
			},
			
			// GitLab Pages
			{
				Service: "GitLab Pages",
				Pattern: "The page you were looking for doesn't exist",
				Notes:   "GitLab Pages 404 with GitLab references",
				Regex:   false,
			},
			{
				Service: "GitLab Pages",
				Pattern: "(?i)gitlab.*pages.*not found|gitlab.*error",
				Notes:   "GitLab Pages error variations",
				Regex:   true,
			},
			
			// Azure Blob Storage
			{
				Service: "Azure Blob Storage",
				Pattern: "The specified container does not exist",
				Notes:   "Azure Blob Storage error",
				Regex:   false,
			},
			{
				Service: "Azure Blob Storage",
				Pattern: "Server failed to authenticate the request",
				Notes:   "Azure authentication error",
				Regex:   false,
			},
			{
				Service: "Azure Blob Storage",
				Pattern: "(?i)azure.*storage.*error|microsoft.*azure",
				Notes:   "Azure error variations",
				Regex:   true,
			},
			
			// Firebase / GCP Hosting
			{
				Service: "Firebase Hosting",
				Pattern: "Project Not Found",
				Notes:   "Firebase project not found",
				Regex:   false,
			},
			{
				Service: "Firebase Hosting",
				Pattern: "(?i)firebase.*hosting.*error|gcp.*hosting.*error",
				Notes:   "Firebase/GCP hosting error variations",
				Regex:   true,
			},
			
			// Surge
			{
				Service: "Surge",
				Pattern: "project not found",
				Notes:   "Surge project not found",
				Regex:   false,
			},
			{
				Service: "Surge",
				Pattern: "(?i)surge.*error|surge.*not found",
				Notes:   "Surge error variations",
				Regex:   true,
			},
			
			// Generic patterns
			{
				Service: "Generic",
				Pattern: "(?i)(site not found|no such site|project not found|there isn't a .* site here|no such app|the specified bucket does not exist|no such host|this page is not available)",
				Notes:   "Generic hosting service error patterns",
				Regex:   true,
			},
		},
	}
}
