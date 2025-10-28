package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"subtake/internal/config"
	"subtake/internal/fingerprints"
	"subtake/internal/scanner"
	"subtake/internal/types"

	"github.com/spf13/cobra"
)

var (
	listFile         string
	outputFile       string
	fingerprintsFile string
	userAgent        string
	insecure         bool
	rate             int
	timeoutRetries   int
	timeout          int
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan [subdomain]",
	Short: "Scan subdomain(s) for takeover vulnerabilities",
	Long: `Scan one or more subdomains for potential takeover vulnerabilities.
You can provide a single subdomain as an argument or use -l to specify a file
containing multiple subdomains (one per line).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&listFile, "list", "l", "", "file containing subdomains (one per line)")
	scanCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file for results (JSON format)")
	scanCmd.Flags().StringVar(&fingerprintsFile, "fingerprints", "", "custom fingerprints file (JSON/YAML)")
	scanCmd.Flags().StringVar(&userAgent, "user-agent", "SubTake/1.0", "user agent string for requests")
	scanCmd.Flags().BoolVar(&insecure, "insecure", false, "allow insecure TLS connections")
	scanCmd.Flags().IntVar(&rate, "rate", 0, "requests per second limit (0 = no limit)")
	scanCmd.Flags().IntVar(&timeoutRetries, "timeout-retries", 1, "number of retries on timeout")
	scanCmd.Flags().IntVar(&timeout, "timeout", 10, "request timeout in seconds")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Show banner
	showBanner()
	// Validate input
	if listFile == "" && len(args) == 0 {
		return fmt.Errorf("must provide either a subdomain argument or use -l/--list")
	}

	// Load configuration
	cfg := &config.Config{
		UserAgent:      userAgent,
		Insecure:       insecure,
		Rate:           rate,
		TimeoutRetries: timeoutRetries,
		Timeout:        time.Duration(timeout) * time.Second,
		Verbose:        verbose,
	}

	// Load fingerprints
	fp, err := fingerprints.Load(fingerprintsFile)
	if err != nil {
		return fmt.Errorf("failed to load fingerprints: %w", err)
	}

	// Get subdomains to scan
	var subdomains []string
	if listFile != "" {
		subdomains, err = loadSubdomainsFromFile(listFile)
		if err != nil {
			return fmt.Errorf("failed to load subdomains from file: %w", err)
		}
	} else {
		subdomains = []string{args[0]}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d subdomains to scan\n", len(subdomains))
		fmt.Fprintf(os.Stderr, "Loaded %d fingerprints\n", len(fp.Fingerprints))
	}

	// Create scanner
	s := scanner.New(cfg, fp)

	// Scan subdomains with real-time output
	results := s.ScanWithRealtimeOutput(subdomains)

	// Output results to file if specified
	if outputFile != "" {
		vulnerableCount := 0
		for _, result := range results {
			if result.Vulnerable && result.Status == "vulnerable" {
				vulnerableCount++
			}
		}

		err = outputToFile(results, outputFile)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "\nResults written to %s (%d vulnerable subdomains)\n", outputFile, vulnerableCount)
		}
	}

	return nil
}

func loadSubdomainsFromFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var subdomains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			subdomains = append(subdomains, line)
		}
	}

	return subdomains, nil
}

func outputToFile(results []types.Result, filename string) error {
	// Filter only vulnerable results
	vulnerableResults := make([]types.Result, 0)
	for _, result := range results {
		if result.Vulnerable && result.Status == "vulnerable" {
			vulnerableResults = append(vulnerableResults, result)
		}
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if dir != "." {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(vulnerableResults)
}
