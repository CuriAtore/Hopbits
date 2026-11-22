// Package cli implements the customer-facing hopbits Monitoring-as-Code & CI/CD CLI.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/hopbits/cli/internal/api"
	"github.com/hopbits/cli/internal/creds"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitError       = 1
	ExitPlanChanges = 2
)

// Env configures I/O, environment lookup, HTTP transport, and version metadata
// for CLI execution and end-to-end testing.
type Env struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Getenv     func(string) string
	HTTPClient *http.Client
	Version    string
}

func (e *Env) withDefaults() Env {
	out := *e
	if out.Stdin == nil {
		out.Stdin = os.Stdin
	}
	if out.Stdout == nil {
		out.Stdout = os.Stdout
	}
	if out.Stderr == nil {
		out.Stderr = os.Stderr
	}
	if out.Getenv == nil {
		out.Getenv = os.Getenv
	}
	if out.Version == "" {
		out.Version = "0.2.0"
	}
	return out
}

func (e Env) userAgent() string {
	return "hopbits-cli/" + e.Version
}

type globalFlags struct {
	apiKey string
	apiURL string
}

func (g *globalFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&g.apiKey, "api-key", g.apiKey, "Hopbits API key (overrides HOPBITS_API_KEY and saved credentials)")
	fs.StringVar(&g.apiURL, "api-url", g.apiURL, "Hopbits API base URL (overrides HOPBITS_API_URL)")
}

func (e Env) newClient(g globalFlags) (*api.Client, creds.Resolved, error) {
	res, err := creds.Resolve(g.apiKey, g.apiURL, e.Getenv)
	if err != nil {
		return nil, res, err
	}
	return api.New(res.APIURL, res.APIKey, e.userAgent(), e.HTTPClient), res, nil
}

// Run executes the hopbits CLI with args (excluding argv[0]) and returns the process exit code.
func Run(ctx context.Context, args []string, env Env) int {
	e := env.withDefaults()

	var g globalFlags
	subArgs := make([]string, 0, len(args))
	var showVersion, showHelp bool

	// Extract leading global flags before the subcommand name.
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(subArgs) > 0 {
			subArgs = append(subArgs, a)
			continue
		}
		switch {
		case a == "--version" || a == "-version" || a == "-v":
			showVersion = true
		case a == "--help" || a == "-help" || a == "-h":
			showHelp = true
		case a == "--api-key" && i+1 < len(args):
			i++
			g.apiKey = args[i]
		case strings.HasPrefix(a, "--api-key="):
			g.apiKey = strings.TrimPrefix(a, "--api-key=")
		case a == "--api-url" && i+1 < len(args):
			i++
			g.apiURL = args[i]
		case strings.HasPrefix(a, "--api-url="):
			g.apiURL = strings.TrimPrefix(a, "--api-url=")
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(e.Stderr, "hopbits: unknown flag %s\n\n", a)
			printRootUsage(e.Stderr)
			return ExitError
		default:
			subArgs = append(subArgs, a)
		}
	}

	if showVersion {
		return e.cmdVersion(nil)
	}
	if showHelp || len(subArgs) == 0 {
		out := e.Stdout
		if !showHelp && len(subArgs) == 0 {
			printRootUsage(out)
			return ExitOK
		}
		printRootUsage(out)
		return ExitOK
	}

	cmd, rest := subArgs[0], subArgs[1:]
	var (
		code int
		err  error
	)
	switch cmd {
	case "version":
		return e.cmdVersion(rest)
	case "help":
		printRootUsage(e.Stdout)
		return ExitOK
	case "login":
		code, err = e.cmdLogin(ctx, g, rest)
	case "whoami":
		code, err = e.cmdWhoami(ctx, g, rest)
	case "plan":
		code, err = e.cmdPlan(ctx, g, rest)
	case "apply":
		code, err = e.cmdApply(ctx, g, rest)
	case "export":
		code, err = e.cmdExport(ctx, g, rest)
	case "probe":
		code, err = e.cmdProbe(ctx, g, rest)
	default:
		fmt.Fprintf(e.Stderr, "hopbits: unknown command %q\n\n", cmd)
		printRootUsage(e.Stderr)
		return ExitError
	}

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		fmt.Fprintf(e.Stderr, "error: %v\n", err)
		if code == ExitOK {
			return ExitError
		}
		return code
	}
	return code
}

func (e Env) cmdVersion(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "Output version info as JSON")
	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if asJSON {
		_ = writeJSON(e.Stdout, map[string]string{
			"version": e.Version,
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		})
		return ExitOK
	}
	fmt.Fprintf(e.Stdout, "hopbits %s (%s/%s)\n", e.Version, runtime.GOOS, runtime.GOARCH)
	return ExitOK
}

func printRootUsage(w io.Writer) {
	fmt.Fprint(w, `hopbits - Monitoring-as-Code & CI/CD CLI for Hopbits

Usage:
  hopbits <command> [flags]

Commands:
  login      Verify and save an API key to local credentials
  whoami     Show account credit balance, monitor count, and live network status
  plan       Preview monitor changes and daily credit estimate against Hopbits
  apply      Reconcile monitors from hopbits.yaml / hopbits.json
  export     Export existing monitors to hopbits.yaml (optionally --adopt keys)
  probe      Run an on-demand global measurement with latency & status gates
  version    Print the CLI version

Global Flags:
  --api-key <key>   API key (overrides HOPBITS_API_KEY / HOPBITS_KEY and credentials file)
  --api-url <url>   API base URL (overrides HOPBITS_API_URL, default https://api.hopbits.io)
  -h, --help        Show help for hopbits or a command
  --version         Print the CLI version
`)
}
