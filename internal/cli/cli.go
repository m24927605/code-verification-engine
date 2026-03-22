package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/verabase/code-verification-engine/internal/claims"
	"github.com/verabase/code-verification-engine/internal/engine"
	"github.com/verabase/code-verification-engine/internal/interpret"
	"github.com/verabase/code-verification-engine/internal/rules"
)

// Version is set via build flags.
var Version = "dev"

// Exit codes per CLI spec.
const (
	ExitSuccess         = 0
	ExitInvalidInput    = 1
	ExitRepoError       = 2
	ExitRuleValidation  = 3
	ExitAnalysisFailure = 4
	ExitReportWrite     = 5
	ExitPartialSuccess  = 6
	ExitCancelled       = 7 // context cancelled or timed out
)

// Run parses CLI arguments and executes the appropriate command.
func Run(args []string) int {
	if len(args) < 1 {
		printUsage()
		return ExitInvalidInput
	}

	switch args[0] {
	case "verify":
		return runVerify(args[1:])
	case "list-profiles":
		return runListProfiles()
	case "list-claims":
		return runListClaims()
	case "version":
		fmt.Printf("cve version %s\n", Version)
		return ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "[ERROR] unknown command: %s\n", args[0])
		printUsage()
		return ExitInvalidInput
	}
}

func runVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	repoPath := fs.String("repo", "", "Local Git repository path (required)")
	ref := fs.String("ref", "HEAD", "Branch, tag, or commit SHA")
	profile := fs.String("profile", "backend-api", "Verification profile name")
	outputDir := fs.String("output", "", "Output directory path (required)")
	format := fs.String("format", "both", "Output format: json, md, both")
	strict := fs.Bool("strict", false, "Fail on any analyzer error")
	claimSetName := fs.String("claims", "", "Claim set name for claim-centric verification (e.g., backend-security)")
	interpretFlag := fs.Bool("interpret", false, "Enable LLM interpretation layer (requires LLM provider)")

	if err := fs.Parse(args); err != nil {
		return ExitInvalidInput
	}

	if *repoPath == "" || *outputDir == "" {
		fmt.Fprintf(os.Stderr, "[ERROR] --repo and --output are required\n")
		return ExitInvalidInput
	}

	if *claimSetName != "" {
		if _, ok := claims.GetClaimSet(*claimSetName); !ok {
			fmt.Fprintf(os.Stderr, "[ERROR] unknown claim set: %s\n", *claimSetName)
			fmt.Fprintf(os.Stderr, "\nAvailable claim sets:\n")
			for name, cs := range claims.AllClaimSets() {
				fmt.Fprintf(os.Stderr, "  %-25s %s (%d claims)\n", name, cs.Description, len(cs.Claims))
			}
			return ExitInvalidInput
		}
	}

	if _, ok := rules.GetProfile(*profile); !ok {
		fmt.Fprintf(os.Stderr, "[ERROR] unknown profile: %s\n", *profile)
		fmt.Fprintf(os.Stderr, "\nAvailable profiles:\n")
		for name, p := range rules.AllProfiles() {
			fmt.Fprintf(os.Stderr, "  %-25s %s (%d rules)\n", name, p.Description, len(p.Rules))
		}
		return ExitInvalidInput
	}

	if *format != "json" && *format != "md" && *format != "both" {
		fmt.Fprintf(os.Stderr, "[ERROR] --format must be json, md, or both\n")
		return ExitInvalidInput
	}

	// Resolve LLM provider for interpretation
	var llmProvider interpret.LLMProvider
	if *interpretFlag {
		apiKey := os.Getenv("CVE_LLM_API_KEY")
		if apiKey == "" {
			fmt.Fprintf(os.Stderr, "[WARN] --interpret: CVE_LLM_API_KEY not set, skipping LLM interpretation\n")
			// Don't set llmProvider — interpretation will be skipped entirely
		} else {
			apiURL := os.Getenv("CVE_LLM_API_URL")
			if apiURL == "" {
				apiURL = "https://api.anthropic.com/v1/messages"
			}
			llmProvider = interpret.NewHTTPProvider(apiKey, apiURL)
		}
	}

	cfg := engine.Config{
		RepoPath:    *repoPath,
		Ref:         *ref,
		Profile:     *profile,
		ClaimSet:    *claimSetName,
		OutputDir:   *outputDir,
		Format:      *format,
		Strict:      *strict,
		Interpret:   *interpretFlag,
		LLMProvider: llmProvider,
		Progress:    os.Stderr,
	}

	result := engine.Run(cfg)
	for _, e := range result.Errors {
		fmt.Fprintf(os.Stderr, "[ERROR] %s\n", e)
	}
	return result.ExitCode
}

func runListProfiles() int {
	profiles := rules.AllProfiles()
	fmt.Println("Available verification profiles:")
	for name, p := range profiles {
		fmt.Printf("\n  %s\n", name)
		fmt.Printf("    %s\n", p.Description)
		fmt.Printf("    %d rules\n\n", len(p.Rules))
		for _, r := range p.Rules {
			fmt.Printf("    [%s] %s (%s/%s)\n", r.ID, r.Title, r.Category, r.Severity)
		}
	}
	fmt.Println()
	return ExitSuccess
}

func runListClaims() int {
	sets := claims.AllClaimSets()
	fmt.Println("Available claim sets:")
	for name, cs := range sets {
		fmt.Printf("\n  %s\n", name)
		fmt.Printf("    %s\n", cs.Description)
		fmt.Printf("    %d claims\n\n", len(cs.Claims))
		for _, c := range cs.Claims {
			fmt.Printf("    [%s] %s\n", c.ID, c.Title)
			fmt.Printf("      Rules: %v\n", c.RuleIDs)
		}
	}
	fmt.Println()
	return ExitSuccess
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: cve <command> [flags]

Commands:
  verify          Run the full verification pipeline
  list-profiles   List available built-in verification profiles
  list-claims     List available claim sets for claim-centric verification
  version         Print version and build metadata

Run 'cve <command> -help' for command-specific flags.

Example:
  cve verify --repo ~/my-api --output ./out
  cve verify --repo ~/my-api --profile backend-api-strict --output ./out
  cve verify --repo ~/my-api --claims backend-security --output ./out
`)
}
