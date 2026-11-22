package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hopbits/cli/internal/api"
	"github.com/hopbits/cli/internal/config"
)

type probeJSONOutput struct {
	ID                string                  `json:"id"`
	Type              string                  `json:"type"`
	Target            string                  `json:"target"`
	Status            string                  `json:"status"`
	Requested         int                     `json:"requested"`
	Assigned          int                     `json:"assigned"`
	OKCount           int                     `json:"ok_count"`
	P50Ms             *float64                `json:"p50_ms,omitempty"`
	P95Ms             *float64                `json:"p95_ms,omitempty"`
	CreditsCharged    int64                   `json:"credits_charged"`
	FailureReason     string                  `json:"failure_reason,omitempty"`
	DiagnosticMessage string                  `json:"diagnostic_message,omitempty"`
	Passed            bool                    `json:"passed"`
	Failures          []string                `json:"failures"`
	Results           []api.MeasurementResult `json:"results"`
}

var (
	allowedDNSQtypes    = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR"}
	allowedDNSResolvers = []string{"isp", "1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"}
)

func (e Env) cmdProbe(ctx context.Context, g globalFlags, args []string) (int, error) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	g.bind(fs)

	var (
		typeFlag     string
		methodFlag   string
		pathFlag     string
		portFlag     int
		familyFlag   string
		fromFlag     string
		limitFlag    int
		networkFlag  string
		qtypeFlag    string
		resolverFlag string
		protoFlag    string
		maxHopsFlag  int
		probesFlag   int
		cyclesFlag   int
		waitFlag     int
		maxCredits   int64
		expectStatus int
		maxP95Raw    string
		minOK        int
		strict       bool
		timeoutDur   time.Duration
		asJSON       bool
	)
	fs.StringVar(&typeFlag, "type", "http", "Probe type: http, tcp, icmp, dns, traceroute, or mtr")
	fs.StringVar(&methodFlag, "method", "", "HTTP method: GET or HEAD")
	fs.StringVar(&pathFlag, "path", "", "HTTP request path (overrides URL path)")
	fs.IntVar(&portFlag, "port", 0, "Destination port (overrides URL port)")
	fs.StringVar(&familyFlag, "family", "", "Address family: ipv4 or ipv6")
	fs.StringVar(&fromFlag, "from", "", "Comma-separated locations (e.g. DE,US,SG or ANY)")
	fs.IntVar(&limitFlag, "limit", 1, "Probes per location (1..10)")
	fs.StringVar(&networkFlag, "network", "any", "Network filter: any, residential, datacenter, or mobile")
	fs.StringVar(&qtypeFlag, "qtype", "", "DNS record type: A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, or PTR")
	fs.StringVar(&resolverFlag, "resolver", "", "DNS resolver: isp, 1.1.1.1, 8.8.8.8, 9.9.9.9, or 208.67.222.222")
	fs.StringVar(&protoFlag, "proto", "", "Transport protocol: udp or tcp (dns); udp or icmp (traceroute, mtr)")
	fs.StringVar(&protoFlag, "protocol", "", "Alias for --proto")
	fs.IntVar(&maxHopsFlag, "max-hops", 0, "Maximum TTL hops for traceroute or mtr (4..30, default 24)")
	fs.IntVar(&probesFlag, "probes", 0, "Probes per hop for traceroute (1..3, default 3)")
	fs.IntVar(&cyclesFlag, "cycles", 0, "Probe cycles for mtr (3..10, default 5)")
	fs.IntVar(&waitFlag, "wait", 0, "Long-poll wait per HTTP poll in seconds (0..25, 0 = auto)")
	fs.Int64Var(&maxCredits, "max-credits", 0, "Maximum credits to reserve (0 for no cap)")
	fs.IntVar(&expectStatus, "expect-status", 0, "Expected HTTP status code (e.g. 200)")
	fs.StringVar(&maxP95Raw, "max-p95", "", "Maximum acceptable p95 RTT (e.g. 500ms, 1.5s)")
	fs.IntVar(&minOK, "min-ok", 1, "Minimum successful probe responses required")
	fs.BoolVar(&strict, "strict", false, "Fail if any assigned or requested probe does not succeed")
	fs.DurationVar(&timeoutDur, "timeout", 35*time.Second, "Maximum wait time for probe completion")
	fs.BoolVar(&asJSON, "json", false, "Output probe report as JSON")

	fs.Usage = func() {
		fmt.Fprint(e.Stderr, `Usage: hopbits probe <target-or-url> [flags]

Runs an on-demand global measurement (http, tcp, icmp, dns, traceroute, mtr)
across Hopbits vantages and evaluates status, reachability, and p95 latency
assertions for diagnostics and CI/CD gates.

Flags:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(permuteArgs(fs, args)); err != nil {
		return ExitError, err
	}
	if len(fs.Args()) != 1 {
		if len(fs.Args()) == 0 {
			return ExitError, fmt.Errorf("missing <target-or-url> argument (usage: hopbits probe <target-or-url> [flags])")
		}
		return ExitError, fmt.Errorf("unexpected extra arguments: %s", strings.Join(fs.Args()[1:], " "))
	}

	kindName, err := config.NormalizeProbeType(typeFlag)
	if err != nil {
		return ExitError, err
	}

	var explicitPort *uint16
	if portFlag != 0 {
		if portFlag < 1 || portFlag > 65535 {
			return ExitError, fmt.Errorf("--port %d must be between 1 and 65535", portFlag)
		}
		switch kindName {
		case "icmp_ping", "dns", "traceroute", "mtr":
			return ExitError, fmt.Errorf("%s probes do not accept --port", kindName)
		}
		p := uint16(portFlag)
		explicitPort = &p
	}

	pt, err := config.ParseTarget(fs.Args()[0], kindName, explicitPort, pathFlag)
	if err != nil {
		return ExitError, err
	}

	family := strings.ToLower(strings.TrimSpace(familyFlag))
	if family != "" && family != "ipv4" && family != "ipv6" {
		return ExitError, fmt.Errorf("--family %q must be ipv4 or ipv6", familyFlag)
	}
	if limitFlag < 1 || limitFlag > 10 {
		return ExitError, fmt.Errorf("--limit %d must be between 1 and 10", limitFlag)
	}
	if minOK < 0 {
		return ExitError, fmt.Errorf("--min-ok %d must be >= 0", minOK)
	}
	if waitFlag < 0 || waitFlag > 25 {
		return ExitError, fmt.Errorf("--wait %d must be between 0 and 25 seconds", waitFlag)
	}

	netFilter := strings.ToLower(strings.TrimSpace(networkFlag))
	switch netFilter {
	case "", "any", "*":
		netFilter = ""
	case "residential", "datacenter", "mobile":
	default:
		return ExitError, fmt.Errorf("--network %q must be any, residential, datacenter, or mobile", networkFlag)
	}

	var maxP95Ms float64
	var hasMaxP95 bool
	if strings.TrimSpace(maxP95Raw) != "" {
		ms, pErr := parseLatencyThresholdMs(maxP95Raw)
		if pErr != nil {
			return ExitError, fmt.Errorf("--max-p95: %w", pErr)
		}
		maxP95Ms = ms
		hasMaxP95 = true
	}

	if expectStatus != 0 && kindName != "http" {
		return ExitError, fmt.Errorf("--expect-status is only valid for --type http")
	}
	if (methodFlag != "" || pathFlag != "") && kindName != "http" {
		return ExitError, fmt.Errorf("--method and --path are only valid for --type http")
	}
	if (qtypeFlag != "" || resolverFlag != "") && kindName != "dns" {
		return ExitError, fmt.Errorf("--qtype and --resolver are only valid for --type dns")
	}
	if protoFlag != "" && kindName != "dns" && kindName != "traceroute" && kindName != "mtr" {
		return ExitError, fmt.Errorf("--proto is only valid for --type dns, traceroute, or mtr")
	}
	if maxHopsFlag != 0 && kindName != "traceroute" && kindName != "mtr" {
		return ExitError, fmt.Errorf("--max-hops is only valid for --type traceroute or mtr")
	}
	if probesFlag != 0 && kindName != "traceroute" {
		return ExitError, fmt.Errorf("--probes is only valid for --type traceroute")
	}
	if cyclesFlag != 0 && kindName != "mtr" {
		return ExitError, fmt.Errorf("--cycles is only valid for --type mtr")
	}

	locs, err := buildProbeLocations(fromFlag, limitFlag, netFilter)
	if err != nil {
		return ExitError, err
	}

	params := map[string]any{}
	switch kindName {
	case "http":
		if mth := strings.ToUpper(strings.TrimSpace(methodFlag)); mth != "" {
			if mth != "GET" && mth != "HEAD" {
				return ExitError, fmt.Errorf("--method %q must be GET or HEAD", methodFlag)
			}
			params["method"] = mth
		}
		if pt.Scheme != "" {
			params["scheme"] = pt.Scheme
		}
		if pt.Path != "" {
			p := pt.Path
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			params["path"] = p
		}
	case "dns":
		if qt := strings.ToUpper(strings.TrimSpace(qtypeFlag)); qt != "" {
			if !slices.Contains(allowedDNSQtypes, qt) {
				return ExitError, fmt.Errorf("--qtype %q must be one of %s", qtypeFlag, strings.Join(allowedDNSQtypes, ", "))
			}
			params["qtype"] = qt
		}
		if res := strings.ToLower(strings.TrimSpace(resolverFlag)); res != "" {
			if !slices.Contains(allowedDNSResolvers, res) {
				return ExitError, fmt.Errorf("--resolver %q must be one of %s", resolverFlag, strings.Join(allowedDNSResolvers, ", "))
			}
			params["resolver"] = res
		}
		if pr := strings.ToLower(strings.TrimSpace(protoFlag)); pr != "" {
			if pr != "udp" && pr != "tcp" {
				return ExitError, fmt.Errorf("--proto %q for dns must be udp or tcp", protoFlag)
			}
			params["protocol"] = pr
		}
	case "traceroute":
		if pr := strings.ToLower(strings.TrimSpace(protoFlag)); pr != "" {
			if pr != "udp" && pr != "icmp" {
				return ExitError, fmt.Errorf("--proto %q for traceroute must be udp or icmp", protoFlag)
			}
			params["protocol"] = pr
		}
		if maxHopsFlag != 0 {
			if maxHopsFlag < 4 || maxHopsFlag > 30 {
				return ExitError, fmt.Errorf("--max-hops %d must be between 4 and 30", maxHopsFlag)
			}
			params["max_hops"] = maxHopsFlag
		}
		if probesFlag != 0 {
			if probesFlag < 1 || probesFlag > 3 {
				return ExitError, fmt.Errorf("--probes %d must be between 1 and 3", probesFlag)
			}
			params["probes"] = probesFlag
		}
	case "mtr":
		if pr := strings.ToLower(strings.TrimSpace(protoFlag)); pr != "" {
			if pr != "udp" && pr != "icmp" {
				return ExitError, fmt.Errorf("--proto %q for mtr must be udp or icmp", protoFlag)
			}
			params["protocol"] = pr
		}
		if maxHopsFlag != 0 {
			if maxHopsFlag < 4 || maxHopsFlag > 30 {
				return ExitError, fmt.Errorf("--max-hops %d must be between 4 and 30", maxHopsFlag)
			}
			params["max_hops"] = maxHopsFlag
		}
		if cyclesFlag != 0 {
			if cyclesFlag < 3 || cyclesFlag > 10 {
				return ExitError, fmt.Errorf("--cycles %d must be between 3 and 10", cyclesFlag)
			}
			params["cycles"] = cyclesFlag
		}
	}

	var reqPort *int
	if pt.Port != nil {
		p := int(*pt.Port)
		reqPort = &p
	}
	var reqParams map[string]any
	if len(params) > 0 {
		reqParams = params
	}

	client, _, err := e.newClient(g)
	if err != nil {
		return ExitError, err
	}

	created, err := client.CreateMeasurement(ctx, api.MeasurementRequest{
		Type:       kindName,
		Target:     pt.Host,
		Port:       reqPort,
		Family:     family,
		Locations:  locs,
		MaxCredits: maxCredits,
		Params:     reqParams,
	})
	if err != nil {
		return ExitError, err
	}

	if timeoutDur <= 0 {
		timeoutDur = 35 * time.Second
	}
	if waitFlag > 0 && time.Duration(waitFlag)*time.Second > timeoutDur {
		timeoutDur = time.Duration(waitFlag+5) * time.Second
	}
	deadline := time.Now().Add(timeoutDur)

	defaultPollWait := 15
	if kindName == "traceroute" || kindName == "mtr" {
		defaultPollWait = 20
	}
	if waitFlag > 0 {
		defaultPollWait = waitFlag
	}

	var m *api.Measurement
	for attempt := 0; ; attempt++ {
		waitSec := defaultPollWait
		if created.Assigned == 0 {
			waitSec = 0
		} else if rem := time.Until(deadline); rem > 0 && rem < time.Duration(waitSec)*time.Second {
			waitSec = max(1, int(math.Ceil(rem.Seconds())))
		}
		callStart := time.Now()
		got, _, gErr := client.GetMeasurement(ctx, created.ID, waitSec)
		if gErr != nil {
			return ExitError, gErr
		}
		m = got
		if m.Complete() || created.Assigned == 0 || !time.Now().Before(deadline) {
			break
		}
		// Avoid tight spinning against mock servers that ignore ?wait=.
		if time.Since(callStart) < 50*time.Millisecond {
			select {
			case <-ctx.Done():
				return ExitError, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	okCount := 0
	var rtts []float64
	for _, r := range m.Results {
		if r.OK() {
			okCount++
			if ms, ok := r.Latency(); ok {
				rtts = append(rtts, ms)
			}
		}
	}
	slices.Sort(rtts)

	var p50Ptr, p95Ptr *float64
	if len(rtts) > 0 {
		p50 := round1(percentile(rtts, 50))
		p95 := round1(percentile(rtts, 95))
		p50Ptr = &p50
		p95Ptr = &p95
	}

	var failures []string
	effectiveMinOK := max(1, minOK)
	if minOK == 0 {
		// Explicit --min-ok 0 still requires okCount > 0 by default per CLI contract:
		// fails if ok_count == 0, OR ok_count < --min-ok.
		effectiveMinOK = 1
	}
	if okCount == 0 {
		msg := "0 probes succeeded"
		if m.DiagnosticMessage != "" {
			msg += ": " + m.DiagnosticMessage
		} else if m.FailureReason != "" {
			msg += " (" + m.FailureReason + ")"
		}
		failures = append(failures, msg)
	} else if okCount < effectiveMinOK {
		failures = append(failures, fmt.Sprintf("only %d probe(s) succeeded (required --min-ok %d)", okCount, effectiveMinOK))
	}

	if strict {
		if m.Requested > 0 && m.Assigned < m.Requested {
			failures = append(failures, fmt.Sprintf("strict mode: only %d of %d requested probes were assigned", m.Assigned, m.Requested))
		}
		if len(m.Results) == 0 || okCount < len(m.Results) || (m.Assigned > 0 && okCount < m.Assigned) {
			failures = append(failures, fmt.Sprintf("strict mode: %d of %d assigned probe(s) succeeded", okCount, max(len(m.Results), m.Assigned)))
		}
	}

	if expectStatus > 0 {
		for idx, r := range m.Results {
			if !r.OK() && r.HTTPStatus() == 0 {
				continue
			}
			gotCode := r.HTTPStatus()
			if gotCode != expectStatus {
				vLabel := r.Country
				if vLabel == "" {
					vLabel = fmt.Sprintf("probe[%d]", idx)
				}
				failures = append(failures, fmt.Sprintf("%s returned HTTP %d (expected %d)", vLabel, gotCode, expectStatus))
			}
		}
	}

	if hasMaxP95 {
		if p95Ptr == nil {
			failures = append(failures, fmt.Sprintf("no RTT samples available to verify --max-p95 %s", maxP95Raw))
		} else if *p95Ptr > maxP95Ms {
			failures = append(failures, fmt.Sprintf("p95 latency %.1fms exceeds --max-p95 %s (%.1fms)", *p95Ptr, maxP95Raw, maxP95Ms))
		}
	}

	passed := len(failures) == 0
	results := m.Results
	if results == nil {
		results = []api.MeasurementResult{}
	}
	failOut := failures
	if failOut == nil {
		failOut = []string{}
	}

	if asJSON {
		_ = writeJSON(e.Stdout, probeJSONOutput{
			ID:                m.ID,
			Type:              m.Type,
			Target:            m.Target,
			Status:            m.Status,
			Requested:         m.Requested,
			Assigned:          m.Assigned,
			OKCount:           okCount,
			P50Ms:             p50Ptr,
			P95Ms:             p95Ptr,
			CreditsCharged:    m.CreditsCharged,
			FailureReason:     m.FailureReason,
			DiagnosticMessage: m.DiagnosticMessage,
			Passed:            passed,
			Failures:          failOut,
			Results:           results,
		})
		if !passed {
			return ExitError, nil
		}
		return ExitOK, nil
	}

	renderProbeTable(e.Stdout, kindName, m, okCount, p50Ptr, p95Ptr)
	if !passed {
		for _, f := range failures {
			fmt.Fprintf(e.Stderr, "assertion failed: %s\n", f)
		}
		return ExitError, nil
	}
	return ExitOK, nil
}

type dnsResultView struct {
	Qname    string `json:"qname"`
	Qtype    string `json:"qtype"`
	Resolver string `json:"resolver"`
	Protocol string `json:"protocol"`
	Rcode    string `json:"rcode"`
	RttUs    uint32 `json:"rtt_us"`
	Answers  []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		TTL  uint32 `json:"ttl"`
		Data string `json:"data"`
	} `json:"answers"`
}

type traceHopView struct {
	Hop      uint32     `json:"hop"`
	IP       string     `json:"ip"`
	Redacted bool       `json:"redacted"`
	ASN      uint32     `json:"asn"`
	ASName   string     `json:"as_name"`
	Country  string     `json:"country"`
	City     string     `json:"city"`
	Sent     uint32     `json:"sent"`
	Received uint32     `json:"received"`
	RttUs    []*uint32  `json:"rtt_us"`
	MinUs    uint32     `json:"min_us"`
	MedianUs uint32     `json:"median_us"`
	MaxUs    uint32     `json:"max_us"`
}

type tracerouteResultView struct {
	Protocol           string         `json:"protocol"`
	DestinationReached bool           `json:"destination_reached"`
	TotalHops          uint32         `json:"total_hops"`
	RttUs              uint32         `json:"rtt_us"`
	Hops               []traceHopView `json:"hops"`
}

type mtrHopView struct {
	Hop      uint32  `json:"hop"`
	IP       string  `json:"ip"`
	Redacted bool    `json:"redacted"`
	ASN      uint32  `json:"asn"`
	ASName   string  `json:"as_name"`
	Country  string  `json:"country"`
	City     string  `json:"city"`
	Sent     uint32  `json:"sent"`
	Received uint32  `json:"received"`
	LossPct  float64 `json:"loss_pct"`
	LastUs   uint32  `json:"last_us"`
	MinUs    uint32  `json:"min_us"`
	AvgUs    uint32  `json:"avg_us"`
	MaxUs    uint32  `json:"max_us"`
	StdevUs  uint32  `json:"stdev_us"`
}

type mtrResultView struct {
	Protocol           string       `json:"protocol"`
	Cycles             uint32       `json:"cycles"`
	DestinationReached bool         `json:"destination_reached"`
	TotalHops          uint32       `json:"total_hops"`
	RttUs              uint32       `json:"rtt_us"`
	Hops               []mtrHopView `json:"hops"`
}

func renderProbeTable(w io.Writer, kindName string, m *api.Measurement, okCount int, p50, p95 *float64) {
	if len(m.Results) > 0 {
		switch kindName {
		case "dns":
			renderDNSTable(w, m)
		case "traceroute":
			renderTracerouteLedgers(w, m)
		case "mtr":
			renderMTRLedgers(w, m)
		default:
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "COUNTRY\tNETWORK\tASN\tSTATUS\tRTT")
			for _, r := range m.Results {
				cc, netClass, asnStr := vantageCols(r)
				statusStr := formatProbeStatus(kindName, r)
				rttStr := "-"
				if ms, ok := r.Latency(); ok {
					rttStr = fmt.Sprintf("%.1fms", ms)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cc, netClass, asnStr, statusStr, rttStr)
			}
			_ = tw.Flush()
			fmt.Fprintln(w)
		}
	} else if m.DiagnosticMessage != "" {
		fmt.Fprintf(w, "Diagnostic: %s\n\n", m.DiagnosticMessage)
	}

	total := max(len(m.Results), m.Assigned)
	if total == 0 {
		total = m.Requested
	}
	p50Str, p95Str := "-", "-"
	if p50 != nil {
		p50Str = fmt.Sprintf("%.1fms", *p50)
	}
	if p95 != nil {
		p95Str = fmt.Sprintf("%.1fms", *p95)
	}
	fmt.Fprintf(w, "Summary: %d/%d ok | p50: %s | p95: %s | credits: %d\n",
		okCount, total, p50Str, p95Str, m.CreditsCharged)
}

func vantageCols(r api.MeasurementResult) (cc, netClass, asnStr string) {
	cc = r.Country
	if cc == "" {
		cc = "-"
	}
	netClass = r.NetworkClass
	if netClass == "" {
		netClass = r.ClientKind
	}
	if netClass == "" {
		netClass = "-"
	}
	asnStr = "-"
	if r.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d", r.ASN)
	}
	return cc, netClass, asnStr
}

func renderDNSTable(w io.Writer, m *api.Measurement) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "COUNTRY\tNETWORK\tASN\tRESOLVER\tSTATUS\tRTT\tANSWERS")
	for _, r := range m.Results {
		cc, netClass, asnStr := vantageCols(r)
		resolverStr := "-"
		statusStr := formatProbeStatus("dns", r)
		rttStr := "-"
		ansStr := "-"
		if len(r.Result) > 0 {
			var dv dnsResultView
			if json.Unmarshal(r.Result, &dv) == nil {
				if dv.Resolver != "" {
					resolverStr = strings.ToUpper(dv.Resolver)
					if dv.Resolver != "isp" {
						resolverStr = dv.Resolver
					}
					if dv.Protocol != "" && dv.Protocol != "udp" {
						resolverStr += "/" + dv.Protocol
					}
				}
				if dv.Rcode != "" {
					statusStr = dv.Rcode
				}
				if dv.RttUs > 0 {
					rttStr = fmt.Sprintf("%.1fms", float64(dv.RttUs)/1000)
				}
				if len(dv.Answers) > 0 {
					parts := make([]string, 0, min(len(dv.Answers), 4))
					for i, a := range dv.Answers {
						if i >= 4 {
							parts = append(parts, fmt.Sprintf("+%d more", len(dv.Answers)-4))
							break
						}
						parts = append(parts, fmt.Sprintf("%s (%ds)", a.Data, a.TTL))
					}
					ansStr = strings.Join(parts, ", ")
				}
			}
		}
		if rttStr == "-" {
			if ms, ok := r.Latency(); ok {
				rttStr = fmt.Sprintf("%.1fms", ms)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cc, netClass, asnStr, resolverStr, statusStr, rttStr, ansStr)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
}

func renderTracerouteLedgers(w io.Writer, m *api.Measurement) {
	for _, r := range m.Results {
		cc, netClass, asnStr := vantageCols(r)
		if !r.OK() || len(r.Result) == 0 {
			fmt.Fprintf(w, "Vantage: %s (%s %s) - %s\n\n", cc, netClass, asnStr, formatProbeStatus("traceroute", r))
			continue
		}
		var tv tracerouteResultView
		if err := json.Unmarshal(r.Result, &tv); err != nil {
			fmt.Fprintf(w, "Vantage: %s (%s %s) - ok\n\n", cc, netClass, asnStr)
			continue
		}
		reachLabel := "partial path"
		if tv.DestinationReached {
			reachLabel = "destination reached"
		}
		endRTT := "-"
		if tv.RttUs > 0 {
			endRTT = fmt.Sprintf("%.1fms", float64(tv.RttUs)/1000)
		}
		proto := tv.Protocol
		if proto == "" {
			proto = "udp"
		}
		fmt.Fprintf(w, "Vantage: %s (%s %s) | %s | %d hops | %s | %s\n",
			cc, netClass, asnStr, proto, tv.TotalHops, reachLabel, endRTT)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  HOP\tROUTER\tNETWORK\tLOCATION\tREPLIES\tRTT")
		for _, h := range tv.Hops {
			router, netLabel, locLabel := formatHopIdentity(h.IP, h.Redacted, h.Received, h.ASN, h.ASName, h.City, h.Country)
			replies := fmt.Sprintf("%d/%d", h.Received, h.Sent)
			rttCol := "-"
			if h.Received > 0 {
				if h.MinUs > 0 && h.MaxUs > 0 {
					rttCol = fmt.Sprintf("%.1f / %.1f / %.1fms",
						float64(h.MinUs)/1000, float64(h.MedianUs)/1000, float64(h.MaxUs)/1000)
				} else if len(h.RttUs) > 0 {
					samples := make([]string, len(h.RttUs))
					for i, s := range h.RttUs {
						if s == nil || *s == 0 {
							samples[i] = "*"
						} else {
							samples[i] = fmt.Sprintf("%.1fms", float64(*s)/1000)
						}
					}
					rttCol = strings.Join(samples, " ")
				}
			}
			fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\t%s\n", h.Hop, router, netLabel, locLabel, replies, rttCol)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}
}

func renderMTRLedgers(w io.Writer, m *api.Measurement) {
	for _, r := range m.Results {
		cc, netClass, asnStr := vantageCols(r)
		if !r.OK() || len(r.Result) == 0 {
			fmt.Fprintf(w, "Vantage: %s (%s %s) - %s\n\n", cc, netClass, asnStr, formatProbeStatus("mtr", r))
			continue
		}
		var mv mtrResultView
		if err := json.Unmarshal(r.Result, &mv); err != nil {
			fmt.Fprintf(w, "Vantage: %s (%s %s) - ok\n\n", cc, netClass, asnStr)
			continue
		}
		reachLabel := "partial path"
		if mv.DestinationReached {
			reachLabel = "destination reached"
		}
		endRTT := "-"
		if mv.RttUs > 0 {
			endRTT = fmt.Sprintf("%.1fms", float64(mv.RttUs)/1000)
		}
		proto := mv.Protocol
		if proto == "" {
			proto = "udp"
		}
		fmt.Fprintf(w, "Vantage: %s (%s %s) | %s | %d cycles | %d hops | %s | %s\n",
			cc, netClass, asnStr, proto, mv.Cycles, mv.TotalHops, reachLabel, endRTT)

		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  HOP\tROUTER\tNETWORK\tLOCATION\tLOSS%\tSNT\tLAST\tAVG\tBEST\tWRST\tSTDEV")
		for _, h := range mv.Hops {
			router, netLabel, locLabel := formatHopIdentity(h.IP, h.Redacted, h.Received, h.ASN, h.ASName, h.City, h.Country)
			fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%.1f%%\t%d\t%s\t%s\t%s\t%s\t%s\n",
				h.Hop, router, netLabel, locLabel, h.LossPct, h.Sent,
				usToMsStr(h.LastUs), usToMsStr(h.AvgUs), usToMsStr(h.MinUs), usToMsStr(h.MaxUs), usToMsStr(h.StdevUs))
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}
}

func formatHopIdentity(ip string, redacted bool, received uint32, asn uint32, asName, city, country string) (router, netLabel, locLabel string) {
	switch {
	case redacted:
		router = "local gateway (hidden)"
	case ip != "":
		router = ip
	case received == 0:
		router = "* * *"
	default:
		router = "-"
	}
	switch {
	case asn > 0 && asName != "":
		netLabel = fmt.Sprintf("AS%d %s", asn, asName)
	case asn > 0:
		netLabel = fmt.Sprintf("AS%d", asn)
	case asName != "":
		netLabel = asName
	default:
		netLabel = "-"
	}
	switch {
	case city != "" && country != "":
		locLabel = fmt.Sprintf("%s, %s", city, country)
	case country != "":
		locLabel = country
	case city != "":
		locLabel = city
	default:
		locLabel = "-"
	}
	return router, netLabel, locLabel
}

func usToMsStr(us uint32) string {
	if us == 0 {
		return "-"
	}
	return fmt.Sprintf("%.1fms", float64(us)/1000)
}

func formatProbeStatus(kindName string, r api.MeasurementResult) string {
	if r.OK() {
		if kindName == "http" || r.HTTPStatus() > 0 {
			if code := r.HTTPStatus(); code > 0 {
				return strconv.Itoa(code)
			}
		}
		return "ok"
	}
	out := r.Outcome
	if out == "" {
		out = "failed"
	}
	if errTxt := r.ErrText(); errTxt != "" && !strings.EqualFold(errTxt, out) {
		return fmt.Sprintf("%s (%s)", out, errTxt)
	}
	return out
}

func buildProbeLocations(fromRaw string, limit int, netFilter string) ([]api.MeasurementLocation, error) {
	trimmed := strings.TrimSpace(fromRaw)
	if trimmed == "" {
		return []api.MeasurementLocation{{
			Country: "ANY",
			Limit:   limit,
			Network: netFilter,
		}}, nil
	}
	parts := strings.Split(trimmed, ",")
	var out []api.MeasurementLocation
	seen := map[string]bool{}
	for _, p := range parts {
		cc := strings.ToUpper(strings.TrimSpace(p))
		if cc == "" {
			continue
		}
		if cc == "*" {
			cc = "ANY"
		}
		if cc != "ANY" && (len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z') {
			return nil, fmt.Errorf("invalid country code %q in --from (expected ISO 2-letter code like DE or ANY)", p)
		}
		if !seen[cc] {
			seen[cc] = true
			out = append(out, api.MeasurementLocation{
				Country: cc,
				Limit:   limit,
				Network: netFilter,
			})
		}
	}
	if len(out) == 0 {
		return []api.MeasurementLocation{{Country: "ANY", Limit: limit, Network: netFilter}}, nil
	}
	if len(out) > 10 {
		return nil, fmt.Errorf("--from accepts at most 10 locations (got %d)", len(out))
	}
	return out, nil
}

func parseLatencyThresholdMs(raw string) (float64, error) {
	s := strings.TrimSpace(raw)
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f <= 0 || math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, fmt.Errorf("threshold %q must be > 0", raw)
		}
		return f, nil
	}
	d, err := time.ParseDuration(strings.ToLower(s))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q (use e.g. 500ms or 1.5s)", raw)
	}
	return float64(d) / float64(time.Millisecond), nil
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil((p/100.0)*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}
