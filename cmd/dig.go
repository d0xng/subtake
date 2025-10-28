package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"subtake/internal/types"

	"github.com/spf13/cobra"
)

var (
	digInputFile  string
	digOutputFile string
)

// digCmd represents the dig command
var digCmd = &cobra.Command{
	Use:   "dig [flags]",
	Short: "Verify vulnerable subdomains using dig command",
	Long: `Dig command verifies previously found vulnerable subdomains by running:
dig <subdomain> ANY +noall +answer

This command reads from a JSON file containing scan results and runs dig
on all subdomains that were marked as vulnerable.`,
	Run: runDig,
}

func init() {
	rootCmd.AddCommand(digCmd)

	digCmd.Flags().StringVarP(&digInputFile, "input", "i", "", "Input JSON file with scan results (required)")
	digCmd.Flags().StringVarP(&digOutputFile, "output", "o", "", "Output file for dig results (default: stdout)")
	digCmd.MarkFlagRequired("input")
}

func runDig(cmd *cobra.Command, args []string) {
	// Load scan results from JSON file
	results, err := loadScanResults(digInputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading scan results: %v\n", err)
		os.Exit(1)
	}

	// Filter vulnerable subdomains
	vulnerableSubdomains := filterVulnerableSubdomains(results)

	if len(vulnerableSubdomains) == 0 {
		fmt.Println("No vulnerable subdomains found in the input file.")
		return
	}

	fmt.Printf("Found %d vulnerable subdomains to verify:\n", len(vulnerableSubdomains))
	for _, subdomain := range vulnerableSubdomains {
		fmt.Printf("- %s\n", subdomain)
	}
	fmt.Println()

	// Run dig on each vulnerable subdomain
	digResults := make([]DigResult, 0, len(vulnerableSubdomains))

	for _, subdomain := range vulnerableSubdomains {
		fmt.Printf("Running dig on %s...\n", subdomain)
		result := runDigCommand(subdomain)
		digResults = append(digResults, result)

		// Print result immediately
		printDigResult(result)
	}

	// Save results to output file if specified
	if digOutputFile != "" {
		err := saveDigResults(digResults, digOutputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error saving results: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nResults saved to: %s\n", digOutputFile)
	}
}

// DigResult represents the result of a dig command
type DigResult struct {
	Subdomain string `json:"subdomain"`
	Command   string `json:"command"`
	Output    string `json:"output"`
	Error     string `json:"error,omitempty"`
	Success   bool   `json:"success"`
}

func loadScanResults(filename string) ([]types.Result, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []types.Result
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&results)
	return results, err
}

func filterVulnerableSubdomains(results []types.Result) []string {
	var vulnerable []string
	for _, result := range results {
		if result.Vulnerable && result.Status == "vulnerable" {
			vulnerable = append(vulnerable, result.Subdomain)
		}
	}
	return vulnerable
}

func runDigCommand(subdomain string) DigResult {
	// Use dig command directly
	cmd := exec.Command("dig", subdomain, "ANY", "+noall", "+answer")
	commandStr := fmt.Sprintf("dig %s ANY +noall +answer", subdomain)

	output, err := cmd.CombinedOutput()

	result := DigResult{
		Subdomain: subdomain,
		Command:   commandStr,
		Output:    string(output),
		Success:   err == nil,
	}

	if err != nil {
		result.Error = err.Error()
	}

	return result
}

func printDigResult(result DigResult) {
	fmt.Printf("\n--- Dig Results for %s ---\n", result.Subdomain)
	fmt.Printf("Command: %s\n", result.Command)

	if result.Success {
		fmt.Printf("Status: SUCCESS\n")
	} else {
		fmt.Printf("Status: ERROR\n")
		fmt.Printf("Error: %s\n", result.Error)
	}

	if result.Output != "" {
		fmt.Printf("Output:\n%s\n", result.Output)
	}
	fmt.Println()
}

func saveDigResults(results []DigResult, filename string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if dir != "" {
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
	return encoder.Encode(results)
}
