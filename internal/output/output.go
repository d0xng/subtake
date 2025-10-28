package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"subtake/internal/types"
)

const (
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorReset  = "\033[0m"
)

// PrintResult prints a single scan result with colors
func PrintResult(result types.Result) {
	status := result.Status
	subdomain := result.Subdomain

	// Color coding based on vulnerability status
	var color string
	switch status {
	case "vulnerable":
		color = ColorGreen
	case "not vulnerable":
		color = ColorRed
	case "error":
		color = ColorYellow
	default:
		color = ColorBlue
	}

	// Print colored status
	fmt.Printf("%s[%s]%s %s", color, strings.ToUpper(status), ColorReset, subdomain)

	// Print evidence if vulnerable
	if result.Vulnerable && len(result.Evidence) > 0 {
		fmt.Printf(" - %s", result.Evidence[0].Service)
		if len(result.Evidence) > 1 {
			fmt.Printf(" (+%d more)", len(result.Evidence)-1)
		}
	}

	// Print error if present
	if result.Error != "" {
		fmt.Printf(" - Error: %s", result.Error)
	}

	fmt.Println()
}

// PrintSummary prints a summary of all results
func PrintSummary(results []types.Result) {
	vulnerable := 0
	notVulnerable := 0
	errors := 0

	for _, result := range results {
		switch result.Status {
		case "vulnerable":
			vulnerable++
		case "not vulnerable":
			notVulnerable++
		case "error":
			errors++
		}
	}

	fmt.Fprintf(os.Stderr, "\n--- Scan Summary ---\n")
	fmt.Fprintf(os.Stderr, "Total subdomains: %d\n", len(results))
	fmt.Fprintf(os.Stderr, "%sVulnerable: %d%s\n", ColorGreen, vulnerable, ColorReset)
	fmt.Fprintf(os.Stderr, "%sNot vulnerable: %d%s\n", ColorRed, notVulnerable, ColorReset)
	fmt.Fprintf(os.Stderr, "%sErrors: %d%s\n", ColorYellow, errors, ColorReset)
}

// PrintJSON prints results in JSON format
func PrintJSON(results []types.Result) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// PrintDetailed prints detailed information about a result
func PrintDetailed(result types.Result) {
	fmt.Printf("\n--- Detailed Results for %s ---\n", result.Subdomain)
	fmt.Printf("Status: %s\n", result.Status)
	fmt.Printf("Vulnerable: %t\n", result.Vulnerable)
	fmt.Printf("Scan Time: %s\n", result.ScanTime.Format("2006-01-02 15:04:05"))

	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
	}

	if len(result.Evidence) > 0 {
		fmt.Println("\nEvidence:")
		for i, evidence := range result.Evidence {
			fmt.Printf("  %d. Service: %s\n", i+1, evidence.Service)
			fmt.Printf("     Pattern: %s\n", evidence.Pattern)
			fmt.Printf("     Notes: %s\n", evidence.Notes)
			fmt.Printf("     Snippet: %s\n", evidence.Snippet)
		}
	}

	if result.HTTPSResponse != nil {
		fmt.Printf("\nHTTPS Response:\n")
		printHTTPResponse(*result.HTTPSResponse)
	}

	if result.HTTPResponse != nil {
		fmt.Printf("\nHTTP Response:\n")
		printHTTPResponse(*result.HTTPResponse)
	}
}

func printHTTPResponse(resp types.HTTPResponse) {
	fmt.Printf("  URL: %s\n", resp.URL)
	fmt.Printf("  Status Code: %d\n", resp.StatusCode)

	if resp.Error != "" {
		fmt.Printf("  Error: %s\n", resp.Error)
		return
	}

	fmt.Printf("  Headers:\n")
	for name, value := range resp.Headers {
		fmt.Printf("    %s: %s\n", name, value)
	}

	// Truncate body for display
	body := resp.Body
	if len(body) > 500 {
		body = body[:500] + "... [truncated]"
	}
	fmt.Printf("  Body: %s\n", body)
}
