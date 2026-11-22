// Package api is a small client for the Hopbits customer API (/v1).
package api

import (
	"encoding/json"
	"strconv"
	"strings"
)

// CheckSpec is one desired monitor as sent to POST /v1/checks/plan and
// PUT /v1/checks/by-key/{key}. Every declarative field is sent explicitly
// (paused and alert_email included) so removing a line from hopbits.yaml
// returns the monitor to its default instead of leaving the old value.
type CheckSpec struct {
	Key             string   `json:"key"`
	Name            string   `json:"name"`
	Type            string   `json:"type"`
	Target          string   `json:"target"`
	Port            *uint16  `json:"port,omitempty"`
	Family          string   `json:"family,omitempty"`
	Method          string   `json:"method,omitempty"`
	Path            string   `json:"path,omitempty"`
	IntervalSeconds int      `json:"interval_seconds"`
	Locations       []string `json:"locations"`
	AlertEmail      bool     `json:"alert_email"`
	WebhookURL      string   `json:"webhook_url"`
	// WebhookSecret is omitted when empty: the server then keeps the
	// existing secret for an unchanged webhook_url.
	WebhookSecret string `json:"webhook_secret,omitempty"`
	Paused        bool   `json:"paused"`
}

// Credits is GET /v1/credits.
type Credits struct {
	Available      int64  `json:"available"`
	GrantAvailable int64  `json:"grant_available"`
	Reserved       int64  `json:"reserved"`
	TotalAvailable int64  `json:"total_available"`
	Currency       string `json:"currency"`
}

// Check is one monitor as GET /v1/checks returns it.
type Check struct {
	ID               string   `json:"id"`
	Key              string   `json:"key,omitempty"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Target           string   `json:"target"`
	Port             uint16   `json:"port,omitempty"`
	Family           string   `json:"family,omitempty"`
	Method           string   `json:"method,omitempty"`
	Path             string   `json:"path,omitempty"`
	IntervalSeconds  int      `json:"interval_seconds"`
	Locations        []string `json:"locations"`
	WebhookURL       string   `json:"webhook_url"`
	HasWebhookSecret bool     `json:"has_webhook_secret"`
	AlertEmail       bool     `json:"alert_email"`
	CreditsPerRun    int      `json:"credits_per_run"`
	SkippedReason    string   `json:"skipped_reason"`
	Verified         bool     `json:"verified"`
	Status           string   `json:"status"`
	Paused           bool     `json:"paused"`
}

// PlanRequest is the body of POST /v1/checks/plan.
type PlanRequest struct {
	Checks []CheckSpec `json:"checks"`
	Prune  bool        `json:"prune"`
}

// Plan actions.
const (
	ActionCreate    = "create"
	ActionUpdate    = "update"
	ActionUnchanged = "unchanged"
	ActionDelete    = "delete"
)

// PlanAction is one entry of a plan.
type PlanAction struct {
	Key                    string   `json:"key"`
	ID                     string   `json:"id,omitempty"`
	Name                   string   `json:"name"`
	Target                 string   `json:"target"`
	Action                 string   `json:"action"`
	ChangedFields          []string `json:"changed_fields"`
	CreditsPerRun          int      `json:"credits_per_run"`
	EstimatedCreditsPerDay int64    `json:"estimated_credits_per_day"`
	SkippedReason          string   `json:"skipped_reason,omitempty"`
}

// PlanSummary counts a plan's actions.
type PlanSummary struct {
	Create                 int   `json:"create"`
	Update                 int   `json:"update"`
	Unchanged              int   `json:"unchanged"`
	Delete                 int   `json:"delete"`
	EstimatedCreditsPerDay int64 `json:"estimated_credits_per_day"`
}

// Changes is create + update + delete.
func (s PlanSummary) Changes() int { return s.Create + s.Update + s.Delete }

// Plan is the answer of POST /v1/checks/plan.
type Plan struct {
	Actions []PlanAction `json:"actions"`
	Summary PlanSummary  `json:"summary"`
}

// CountryNodes is one country of GET /v1/network.
type CountryNodes struct {
	Country string `json:"country"`
	Nodes   int    `json:"nodes_online"`
}

// Network is GET /v1/network, read tolerantly: online_nodes or online, and
// per-country nodes_online, nodes or count (a number or a numeric string),
// with countries as a list of objects or a {"DE": 3} map.
type Network struct {
	OnlineNodes int            `json:"online_nodes"`
	Countries   []CountryNodes `json:"countries"`
}

// UnmarshalJSON implements the tolerant decoding described on Network.
func (n *Network) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	n.OnlineNodes = firstInt(raw, "online_nodes", "online", "nodes_online", "nodes")
	n.Countries = nil
	if c, ok := raw["countries"]; ok {
		var list []map[string]json.RawMessage
		if json.Unmarshal(c, &list) == nil {
			for _, item := range list {
				var cc string
				for _, k := range []string{"country", "code", "cc"} {
					if v, ok := item[k]; ok && json.Unmarshal(v, &cc) == nil && cc != "" {
						break
					}
				}
				n.Countries = append(n.Countries, CountryNodes{
					Country: strings.ToUpper(cc),
					Nodes:   firstInt(item, "nodes_online", "nodes", "online", "count"),
				})
			}
		} else {
			var m map[string]json.RawMessage
			if json.Unmarshal(c, &m) == nil {
				for cc, v := range m {
					n.Countries = append(n.Countries, CountryNodes{Country: strings.ToUpper(cc), Nodes: toInt(v)})
				}
			}
		}
	}
	if n.OnlineNodes == 0 {
		for _, c := range n.Countries {
			n.OnlineNodes += c.Nodes
		}
	}
	return nil
}

func firstInt(m map[string]json.RawMessage, keys ...string) int {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if n := toInt(v); n != 0 {
				return n
			}
		}
	}
	return 0
}

func toInt(v json.RawMessage) int {
	var f float64
	if json.Unmarshal(v, &f) == nil {
		return int(f)
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return n
		}
	}
	return 0
}

// MeasurementLocation is one location selector of POST /v1/measurements.
type MeasurementLocation struct {
	Country string `json:"country"`
	Limit   int    `json:"limit,omitempty"`
	Network string `json:"network,omitempty"`
}

// MeasurementRequest is the body of POST /v1/measurements.
type MeasurementRequest struct {
	Type       string                `json:"type"`
	Target     string                `json:"target"`
	Port       *int                  `json:"port,omitempty"`
	Family     string                `json:"family,omitempty"`
	Locations  []MeasurementLocation `json:"locations,omitempty"`
	MaxCredits int64                 `json:"max_credits,omitempty"`
	Params     map[string]any        `json:"params,omitempty"`
}

// MeasurementCreated is the 202 answer of POST /v1/measurements.
type MeasurementCreated struct {
	ID                string `json:"id"`
	Requested         int    `json:"requested"`
	Assigned          int    `json:"assigned"`
	CreditsReserved   int64  `json:"credits_reserved"`
	FailureReason     string `json:"failure_reason,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
	DiagnosticMessage string `json:"diagnostic_message,omitempty"`
}

// Measurement statuses.
const (
	StatusInProgress = "in-progress"
	StatusFinished   = "finished"
)

// Measurement is GET /v1/measurements/{id}.
type Measurement struct {
	ID                string              `json:"id"`
	Type              string              `json:"type"`
	Target            string              `json:"target"`
	Address           string              `json:"address,omitempty"`
	Port              int                 `json:"port,omitempty"`
	Status            string              `json:"status"`
	Requested         int                 `json:"requested"`
	Assigned          int                 `json:"assigned"`
	CreditsReserved   int64               `json:"credits_reserved"`
	CreditsCharged    int64               `json:"credits_charged"`
	FailureReason     string              `json:"failure_reason,omitempty"`
	RetryAfterSeconds int                 `json:"retry_after_seconds,omitempty"`
	DiagnosticMessage string              `json:"diagnostic_message,omitempty"`
	Results           []MeasurementResult `json:"results"`
}

// Complete reports whether every assigned probe has answered.
func (m *Measurement) Complete() bool {
	if m == nil {
		return false
	}
	if strings.EqualFold(m.Status, StatusFinished) {
		return true
	}
	return m.Assigned > 0 && len(m.Results) >= m.Assigned
}

// MeasurementResult is one vantage's answer.
type MeasurementResult struct {
	Node         string          `json:"node,omitempty"`
	Country      string          `json:"country,omitempty"`
	ASN          uint32          `json:"asn,omitempty"`
	NetworkClass string          `json:"network_class,omitempty"`
	ClientKind   string          `json:"client_kind,omitempty"`
	Outcome      string          `json:"outcome"`
	Error        string          `json:"error,omitempty"`
	ErrorCode    string          `json:"error_code,omitempty"`
	RTTMs        *float64        `json:"rtt_ms,omitempty"`
	StatusCode   int             `json:"status_code,omitempty"`
	Timings      json.RawMessage `json:"timings,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
}

// OK reports a probe that answered: outcome "ok" with no error.
func (r MeasurementResult) OK() bool {
	return strings.EqualFold(strings.TrimSpace(r.Outcome), "ok") && r.Error == "" && r.ErrorCode == ""
}

// HTTPStatus is the HTTP status code the probe saw, or 0.
func (r MeasurementResult) HTTPStatus() int {
	if r.StatusCode != 0 {
		return r.StatusCode
	}
	var v struct {
		StatusCode int `json:"status_code"`
	}
	if len(r.Result) > 0 && json.Unmarshal(r.Result, &v) == nil {
		return v.StatusCode
	}
	return 0
}

// Latency returns the probe's round trip in milliseconds: rtt_ms when the
// server sends it, else http phases.total_us, else median_us / min_us of a
// tcp_connect or icmp_ping result (or fallback timings).
func (r MeasurementResult) Latency() (float64, bool) {
	if r.RTTMs != nil && *r.RTTMs > 0 {
		return *r.RTTMs, true
	}
	if len(r.Result) > 0 {
		var v struct {
			RTTMs  float64 `json:"rtt_ms"`
			RTTUS  float64 `json:"rtt_us"`
			Phases *struct {
				TotalUS     float64 `json:"total_us"`
				FirstByteUS float64 `json:"first_byte_us"`
			} `json:"phases"`
			MedianUS float64 `json:"median_us"`
			MinUS    float64 `json:"min_us"`
		}
		if json.Unmarshal(r.Result, &v) == nil {
			switch {
			case v.RTTMs > 0:
				return v.RTTMs, true
			case v.Phases != nil && v.Phases.TotalUS > 0:
				return v.Phases.TotalUS / 1000, true
			case v.Phases != nil && v.Phases.FirstByteUS > 0:
				return v.Phases.FirstByteUS / 1000, true
			case v.MedianUS > 0:
				return v.MedianUS / 1000, true
			case v.MinUS > 0:
				return v.MinUS / 1000, true
			case v.RTTUS > 0:
				return v.RTTUS / 1000, true
			}
		}
	}
	if len(r.Timings) > 0 {
		var t struct {
			TotalMS float64 `json:"total_ms"`
			RTTMs   float64 `json:"rtt_ms"`
			TotalUS float64 `json:"total_us"`
		}
		if json.Unmarshal(r.Timings, &t) == nil {
			switch {
			case t.TotalMS > 0:
				return t.TotalMS, true
			case t.RTTMs > 0:
				return t.RTTMs, true
			case t.TotalUS > 0:
				return t.TotalUS / 1000, true
			}
		}
	}
	return 0, false
}

// ErrText is the probe's error, from error or error_code.
func (r MeasurementResult) ErrText() string {
	if r.Error != "" {
		return r.Error
	}
	return r.ErrorCode
}
