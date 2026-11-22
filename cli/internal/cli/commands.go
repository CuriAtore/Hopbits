package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hopbits/cli/internal/api"
	"github.com/hopbits/cli/internal/config"
	"github.com/hopbits/cli/internal/creds"
)

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (e Env) cmdLogin(ctx context.Context, g globalFlags, args []string) (int, error) {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	g.bind(fs)
	fs.Usage = func() {
		fmt.Fprint(e.Stderr, `Usage: hopbits login [--api-key <key>] [--api-url <url>]

Verifies your Hopbits API key against GET /v1/credits and saves it to
~/.config/hopbits/credentials (or %APPDATA%\hopbits\credentials on Windows)
with mode 0600.
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		return ExitError, err
	}

	key := strings.TrimSpace(g.apiKey)
	if key == "" && len(fs.Args()) == 1 {
		key = strings.TrimSpace(fs.Args()[0])
	} else if len(fs.Args()) > 1 {
		return ExitError, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	if key == "" {
		fmt.Fprint(e.Stderr, "Enter your Hopbits API key (hb_live_...): ")
		rd := bufio.NewReader(e.Stdin)
		line, err := rd.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return ExitError, fmt.Errorf("reading API key: %w", err)
		}
		key = strings.TrimSpace(line)
	}
	if key == "" {
		return ExitError, errors.New("API key cannot be empty")
	}

	explicitURL := strings.TrimRight(strings.TrimSpace(g.apiURL), "/")
	apiURL := explicitURL
	if apiURL == "" {
		if envURL := strings.TrimRight(strings.TrimSpace(e.Getenv("HOPBITS_API_URL")), "/"); envURL != "" {
			apiURL = envURL
		} else {
			apiURL = api.DefaultBaseURL
		}
	}

	client := api.New(apiURL, key, e.userAgent(), e.HTTPClient)
	bal, err := client.Credits(ctx)
	if err != nil {
		return ExitError, fmt.Errorf("verifying API key against %s/v1/credits: %w", apiURL, err)
	}

	credPath, err := creds.CredentialsPath(e.Getenv)
	if err != nil {
		return ExitError, err
	}
	toSave := creds.Stored{APIKey: key}
	if apiURL != api.DefaultBaseURL {
		toSave.APIURL = apiURL
	}
	if err := creds.Save(credPath, toSave); err != nil {
		return ExitError, err
	}

	fmt.Fprintf(e.Stdout, "Authenticated with %s (%d credits available).\n", apiURL, bal.TotalAvailable)
	fmt.Fprintf(e.Stdout, "Saved credentials to %s (mode 0600).\n", credPath)
	return ExitOK, nil
}

type whoamiOutput struct {
	APIURL     string          `json:"api_url"`
	AuthSource string          `json:"auth_source"`
	Credits    *api.Credits    `json:"credits"`
	Checks     whoamiChecks    `json:"checks"`
	Network    whoamiNetwork   `json:"network"`
}

type whoamiChecks struct {
	Total  int `json:"total"`
	Active int `json:"active"`
	Paused int `json:"paused"`
}

type whoamiNetwork struct {
	OnlineNodes     int                `json:"online_nodes"`
	CountriesOnline int                `json:"countries_online"`
	Countries       []api.CountryNodes `json:"countries"`
}

func (e Env) cmdWhoami(ctx context.Context, g globalFlags, args []string) (int, error) {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	g.bind(fs)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "Output account and network status as JSON")
	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		return ExitError, err
	}
	if len(fs.Args()) > 0 {
		return ExitError, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	client, resolved, err := e.newClient(g)
	if err != nil {
		return ExitError, err
	}

	bal, err := client.Credits(ctx)
	if err != nil {
		return ExitError, err
	}
	checks, err := client.ListChecks(ctx)
	if err != nil {
		return ExitError, err
	}
	netView, err := client.Network(ctx)
	if err != nil {
		return ExitError, err
	}

	active, paused := 0, 0
	for _, c := range checks {
		if c.Paused {
			paused++
		} else {
			active++
		}
	}
	countriesOnline := 0
	for _, c := range netView.Countries {
		if c.Nodes > 0 {
			countriesOnline++
		}
	}
	if countriesOnline == 0 && len(netView.Countries) > 0 {
		countriesOnline = len(netView.Countries)
	}

	out := whoamiOutput{
		APIURL:     resolved.APIURL,
		AuthSource: resolved.Source,
		Credits:    bal,
		Checks: whoamiChecks{
			Total:  len(checks),
			Active: active,
			Paused: paused,
		},
		Network: whoamiNetwork{
			OnlineNodes:     netView.OnlineNodes,
			CountriesOnline: countriesOnline,
			Countries:       netView.Countries,
		},
	}

	if asJSON {
		return ExitOK, writeJSON(e.Stdout, out)
	}

	fmt.Fprintf(e.Stdout, "Endpoint:  %s (auth via %s)\n", out.APIURL, out.AuthSource)
	if bal.GrantAvailable > 0 || bal.Reserved > 0 {
		fmt.Fprintf(e.Stdout, "Credits:   %d available (%d purchased, %d grant, %d reserved)\n",
			bal.TotalAvailable, bal.Available, bal.GrantAvailable, bal.Reserved)
	} else {
		fmt.Fprintf(e.Stdout, "Credits:   %d available\n", bal.TotalAvailable)
	}
	fmt.Fprintf(e.Stdout, "Monitors:  %d active, %d paused (%d total)\n", active, paused, len(checks))
	fmt.Fprintf(e.Stdout, "Network:   %d online nodes across %d countries\n", netView.OnlineNodes, countriesOnline)
	return ExitOK, nil
}

type planJSONOutput struct {
	File    string           `json:"file"`
	Prune   bool             `json:"prune"`
	Actions []api.PlanAction `json:"actions"`
	Summary api.PlanSummary  `json:"summary"`
	Credits *api.Credits     `json:"credits,omitempty"`
}

func (e Env) cmdPlan(ctx context.Context, g globalFlags, args []string) (int, error) {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	g.bind(fs)
	var (
		fileFlag         string
		prune            bool
		detailedExitCode bool
		asJSON           bool
	)
	fs.StringVar(&fileFlag, "f", "", "Path to hopbits.yaml or hopbits.json")
	fs.StringVar(&fileFlag, "file", "", "Path to hopbits.yaml or hopbits.json")
	fs.BoolVar(&prune, "prune", false, "Include deletions for managed (keyed) monitors absent from config")
	fs.BoolVar(&detailedExitCode, "detailed-exitcode", false, "Exit 2 when changes are present, 0 when unchanged, 1 on error")
	fs.BoolVar(&asJSON, "json", false, "Output plan as JSON")
	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		return ExitError, err
	}
	if len(fs.Args()) > 0 {
		return ExitError, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	cfgPath := config.ResolveFilePath(fileFlag)
	cfg, err := config.LoadFile(cfgPath, e.Getenv)
	if err != nil {
		return ExitError, err
	}

	client, _, err := e.newClient(g)
	if err != nil {
		return ExitError, err
	}

	plan, err := client.Plan(ctx, api.PlanRequest{
		Checks: cfg.Monitors,
		Prune:  prune,
	})
	if err != nil {
		return ExitError, err
	}
	bal, _ := client.Credits(ctx)

	if asJSON {
		if err := writeJSON(e.Stdout, planJSONOutput{
			File:    cfg.Path,
			Prune:   prune,
			Actions: nonNilActions(plan.Actions),
			Summary: plan.Summary,
			Credits: bal,
		}); err != nil {
			return ExitError, err
		}
	} else {
		renderPlanText(e.Stdout, plan, bal)
	}

	if detailedExitCode && plan.Summary.Changes() > 0 {
		return ExitPlanChanges, nil
	}
	return ExitOK, nil
}

func renderPlanText(w io.Writer, plan *api.Plan, bal *api.Credits) {
	if len(plan.Actions) == 0 {
		fmt.Fprintln(w, "No monitors in configuration or remote plan.")
	}
	for _, a := range plan.Actions {
		label := a.Key
		if a.Name != "" && a.Name != a.Key {
			label = fmt.Sprintf("%s (%s -> %s)", a.Key, a.Name, a.Target)
		} else if a.Target != "" {
			label = fmt.Sprintf("%s (%s)", a.Key, a.Target)
		}
		switch a.Action {
		case api.ActionCreate:
			fmt.Fprintf(w, "  + create    %s  [~%d credits/day]\n", label, a.EstimatedCreditsPerDay)
		case api.ActionUpdate:
			changed := strings.Join(a.ChangedFields, ", ")
			if changed == "" {
				changed = "fields"
			}
			fmt.Fprintf(w, "  ~ update    %s  (changed: %s)\n", label, changed)
		case api.ActionUnchanged:
			fmt.Fprintf(w, "  = unchanged %s\n", label)
		case api.ActionDelete:
			fmt.Fprintf(w, "  - delete    %s\n", label)
		default:
			fmt.Fprintf(w, "  ? %-9s %s\n", a.Action, label)
		}
		if a.SkippedReason != "" && a.Action != api.ActionDelete {
			fmt.Fprintf(w, "    ! warning (%s): runs will be skipped (%s)\n", a.Key, a.SkippedReason)
		}
	}
	if len(plan.Actions) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Plan: %d to create, %d to update, %d to delete, %d unchanged.\n",
		plan.Summary.Create, plan.Summary.Update, plan.Summary.Delete, plan.Summary.Unchanged)
	if bal != nil {
		fmt.Fprintf(w, "Estimated spend: ~%d credits/day (available balance: %d credits).\n",
			plan.Summary.EstimatedCreditsPerDay, bal.TotalAvailable)
		if plan.Summary.EstimatedCreditsPerDay > bal.TotalAvailable {
			fmt.Fprintf(w, "Warning: estimated daily spend (%d) exceeds current available credits (%d).\n",
				plan.Summary.EstimatedCreditsPerDay, bal.TotalAvailable)
		}
	} else {
		fmt.Fprintf(w, "Estimated spend: ~%d credits/day.\n", plan.Summary.EstimatedCreditsPerDay)
	}
}

type applyJSONOutput struct {
	File      string          `json:"file"`
	DryRun    bool            `json:"dry_run"`
	Prune     bool            `json:"prune"`
	Plan      *api.Plan       `json:"plan"`
	Credits   *api.Credits    `json:"credits,omitempty"`
	Created   []string        `json:"created"`
	Updated   []string        `json:"updated"`
	Deleted   []string        `json:"deleted"`
	Unchanged []string        `json:"unchanged"`
}

func (e Env) cmdApply(ctx context.Context, g globalFlags, args []string) (int, error) {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	g.bind(fs)
	var (
		fileFlag string
		prune    bool
		dryRun   bool
		asJSON   bool
	)
	fs.StringVar(&fileFlag, "f", "", "Path to hopbits.yaml or hopbits.json")
	fs.StringVar(&fileFlag, "file", "", "Path to hopbits.yaml or hopbits.json")
	fs.BoolVar(&prune, "prune", false, "Delete managed (keyed) monitors absent from config")
	fs.BoolVar(&dryRun, "dry-run", false, "Run plan and stop without modifying monitors")
	fs.BoolVar(&asJSON, "json", false, "Output apply summary as JSON")
	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		return ExitError, err
	}
	if len(fs.Args()) > 0 {
		return ExitError, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	cfgPath := config.ResolveFilePath(fileFlag)
	cfg, err := config.LoadFile(cfgPath, e.Getenv)
	if err != nil {
		return ExitError, err
	}

	client, _, err := e.newClient(g)
	if err != nil {
		return ExitError, err
	}

	plan, err := client.Plan(ctx, api.PlanRequest{
		Checks: cfg.Monitors,
		Prune:  prune,
	})
	if err != nil {
		return ExitError, err
	}
	bal, _ := client.Credits(ctx)

	out := applyJSONOutput{
		File:      cfg.Path,
		DryRun:    dryRun,
		Prune:     prune,
		Plan:      plan,
		Credits:   bal,
		Created:   []string{},
		Updated:   []string{},
		Deleted:   []string{},
		Unchanged: []string{},
	}

	if dryRun {
		if asJSON {
			return ExitOK, writeJSON(e.Stdout, out)
		}
		renderPlanText(e.Stdout, plan, bal)
		fmt.Fprintln(e.Stdout, "Dry run complete: no changes applied.")
		return ExitOK, nil
	}

	byKey := make(map[string]api.CheckSpec, len(cfg.Monitors))
	for _, spec := range cfg.Monitors {
		byKey[spec.Key] = spec
	}

	if !asJSON {
		renderPlanText(e.Stdout, plan, bal)
	}

	if plan.Summary.Changes() == 0 {
		for _, a := range plan.Actions {
			if a.Action == api.ActionUnchanged {
				out.Unchanged = append(out.Unchanged, a.Key)
			}
		}
		if asJSON {
			return ExitOK, writeJSON(e.Stdout, out)
		}
		fmt.Fprintln(e.Stdout, "Everything up to date (0 changes).")
		return ExitOK, nil
	}

	if !asJSON {
		fmt.Fprintln(e.Stdout)
	}

	for _, a := range plan.Actions {
		switch a.Action {
		case api.ActionCreate, api.ActionUpdate:
			spec, ok := byKey[a.Key]
			if !ok {
				return ExitError, fmt.Errorf("internal plan mismatch: missing spec for key %q", a.Key)
			}
			chk, created, uErr := client.PutCheck(ctx, spec)
			if uErr != nil {
				return ExitError, fmt.Errorf("applying monitor %q: %w", a.Key, uErr)
			}
			if created || a.Action == api.ActionCreate {
				out.Created = append(out.Created, a.Key)
				if !asJSON {
					fmt.Fprintf(e.Stdout, "  + created %s (%s)\n", a.Key, chk.ID)
				}
			} else {
				out.Updated = append(out.Updated, a.Key)
				if !asJSON {
					fmt.Fprintf(e.Stdout, "  ~ updated %s (%s)\n", a.Key, chk.ID)
				}
			}
			if chk.SkippedReason != "" && !asJSON {
				fmt.Fprintf(e.Stdout, "    ! warning (%s): runs will be skipped (%s)\n", a.Key, chk.SkippedReason)
			}
		case api.ActionDelete:
			// Client-side safety invariant: never delete unless --prune was requested
			// and the check carries a non-empty declarative key.
			if !prune || a.Key == "" {
				continue
			}
			if dErr := client.DeleteCheckByKey(ctx, a.Key); dErr != nil {
				return ExitError, fmt.Errorf("deleting monitor %q: %w", a.Key, dErr)
			}
			out.Deleted = append(out.Deleted, a.Key)
			if !asJSON {
				fmt.Fprintf(e.Stdout, "  - deleted %s\n", a.Key)
			}
		case api.ActionUnchanged:
			out.Unchanged = append(out.Unchanged, a.Key)
		}
	}

	if asJSON {
		return ExitOK, writeJSON(e.Stdout, out)
	}
	fmt.Fprintf(e.Stdout, "\nApply complete: %d created, %d updated, %d deleted, %d unchanged.\n",
		len(out.Created), len(out.Updated), len(out.Deleted), len(out.Unchanged))
	return ExitOK, nil
}

func (e Env) cmdExport(ctx context.Context, g globalFlags, args []string) (int, error) {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	g.bind(fs)
	var (
		outPath string
		adopt   bool
		force   bool
	)
	fs.StringVar(&outPath, "o", "hopbits.yaml", "Output file path, or '-' for stdout")
	fs.StringVar(&outPath, "output", "hopbits.yaml", "Output file path, or '-' for stdout")
	fs.BoolVar(&adopt, "adopt", false, "Assign generated keys to unkeyed remote monitors via PATCH /v1/checks/{id}")
	fs.BoolVar(&force, "force", false, "Overwrite output file if it already exists")
	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		return ExitError, err
	}
	if len(fs.Args()) > 0 {
		return ExitError, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	outPath = strings.TrimSpace(outPath)
	if outPath == "" {
		outPath = "hopbits.yaml"
	}
	toStdout := outPath == "-"
	if !toStdout && !force {
		if _, err := os.Stat(outPath); err == nil {
			return ExitError, fmt.Errorf("refusing to overwrite existing %s (pass --force to overwrite or -o - for stdout)", outPath)
		}
	}

	client, _, err := e.newClient(g)
	if err != nil {
		return ExitError, err
	}

	checks, err := client.ListChecks(ctx)
	if err != nil {
		return ExitError, err
	}

	used := make(map[string]bool, len(checks))
	for _, c := range checks {
		if c.Key != "" {
			used[c.Key] = true
		}
	}

	type adoption struct {
		idx int
		id  string
		key string
	}
	var toAdopt []adoption
	for i := range checks {
		if checks[i].Key == "" {
			gen := config.GenerateSlug(checks[i].Name, checks[i].Target, used)
			checks[i].Key = gen
			toAdopt = append(toAdopt, adoption{idx: i, id: checks[i].ID, key: gen})
		}
	}

	logW := e.Stdout
	if toStdout {
		logW = e.Stderr
	}

	if adopt {
		for _, a := range toAdopt {
			if err := client.SetCheckKey(ctx, a.id, a.key); err != nil {
				return ExitError, fmt.Errorf("adopting monitor %s with key %q: %w", a.id, a.key, err)
			}
			fmt.Fprintf(logW, "Adopted monitor %s -> key %q\n", a.id, a.key)
		}
	}

	yamlBytes, err := config.RenderYAML(checks)
	if err != nil {
		return ExitError, fmt.Errorf("rendering YAML: %w", err)
	}

	if toStdout {
		if _, err := e.Stdout.Write(yamlBytes); err != nil {
			return ExitError, err
		}
		if !adopt && len(toAdopt) > 0 {
			fmt.Fprintf(e.Stderr, "Note: generated keys for %d unkeyed monitor(s); re-run with --adopt to bind them in place before 'hopbits apply'.\n", len(toAdopt))
		}
		return ExitOK, nil
	}

	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return ExitError, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(outPath, yamlBytes, 0o644); err != nil {
		return ExitError, fmt.Errorf("writing %s: %w", outPath, err)
	}

	fmt.Fprintf(logW, "Exported %d monitor(s) to %s", len(checks), outPath)
	if adopt && len(toAdopt) > 0 {
		fmt.Fprintf(logW, " (adopted %d unkeyed monitor(s)).\n", len(toAdopt))
	} else {
		fmt.Fprintln(logW, ".")
		if len(toAdopt) > 0 {
			fmt.Fprintf(logW, "Note: generated keys for %d unkeyed monitor(s); run 'hopbits export --adopt --force -o %s' to bind them in place without recreating.\n", len(toAdopt), outPath)
		}
	}
	return ExitOK, nil
}

func nonNilActions(in []api.PlanAction) []api.PlanAction {
	if in == nil {
		return []api.PlanAction{}
	}
	return in
}
