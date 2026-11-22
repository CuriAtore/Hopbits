package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the production API.
const DefaultBaseURL = "https://api.hopbits.io"

// Error is a non-2xx answer from the API.
type Error struct {
	Method  string
	Path    string
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	msg := e.Message
	if msg == "" {
		msg = strings.ToLower(http.StatusText(e.Status))
	}
	if e.Code != "" {
		return fmt.Sprintf("%s %s: %d %s: %s", e.Method, e.Path, e.Status, e.Code, msg)
	}
	return fmt.Sprintf("%s %s: %d: %s", e.Method, e.Path, e.Status, msg)
}

// IsStatus reports whether err is an *Error with the given HTTP status.
func IsStatus(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == status
}

// Client talks to the Hopbits API.
type Client struct {
	BaseURL   string
	APIKey    string
	UserAgent string
	HTTP      *http.Client
	// Retries is how many times an idempotent request is retried after a
	// network error or a 502/503/504. RetryWait is the first backoff.
	Retries   int
	RetryWait time.Duration
}

// New returns a client with sensible defaults.
func New(baseURL, apiKey, userAgent string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &Client{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		APIKey:    apiKey,
		UserAgent: userAgent,
		HTTP:      hc,
		Retries:   2,
		RetryWait: 500 * time.Millisecond,
	}
}

// Do sends one request. body (if not nil) is JSON-encoded, out (if not nil)
// receives the decoded JSON answer. It returns the HTTP status.
func (c *Client) Do(ctx context.Context, method, path string, body, out any, idempotent bool) (int, error) {
	var payload []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		payload = b
	}
	attempts := 1
	if idempotent && c.Retries > 0 {
		attempts += c.Retries
	}
	wait := c.RetryWait
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(wait):
			}
			wait *= 2
		}
		status, retry, err := c.once(ctx, method, path, payload, body != nil, out)
		if err == nil {
			return status, nil
		}
		lastErr = err
		if !retry || ctx.Err() != nil {
			return status, err
		}
	}
	return 0, lastErr
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte, hasBody bool, out any) (status int, retry bool, err error) {
	var rd io.Reader
	if hasBody {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
	if err != nil {
		return 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	if hasBody {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, true, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, true, fmt.Errorf("%s %s: reading answer: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &Error{Method: method, Path: stripQuery(path), Status: resp.StatusCode}
		var eb struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &eb) == nil && (eb.Error.Code != "" || eb.Error.Message != "") {
			apiErr.Code, apiErr.Message = eb.Error.Code, eb.Error.Message
		} else if t := strings.TrimSpace(string(data)); t != "" && len(t) < 300 {
			apiErr.Message = t
		}
		switch resp.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			retry = true
		}
		return resp.StatusCode, retry, apiErr
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, false, fmt.Errorf("%s %s: decoding answer: %w", method, stripQuery(path), err)
		}
	}
	return resp.StatusCode, false, nil
}

func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// Credits is GET /v1/credits.
func (c *Client) Credits(ctx context.Context) (*Credits, error) {
	var out Credits
	if _, err := c.Do(ctx, http.MethodGet, "/v1/credits", nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// Network is GET /v1/network.
func (c *Client) Network(ctx context.Context) (*Network, error) {
	var out Network
	if _, err := c.Do(ctx, http.MethodGet, "/v1/network", nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListChecks is GET /v1/checks. It accepts {"checks": [...]} or a bare list.
func (c *Client) ListChecks(ctx context.Context) ([]Check, error) {
	var raw json.RawMessage
	if _, err := c.Do(ctx, http.MethodGet, "/v1/checks", nil, &raw, true); err != nil {
		return nil, err
	}
	var wrapped struct {
		Checks []Check `json:"checks"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Checks, nil
	}
	var list []Check
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("GET /v1/checks: unexpected answer: %w", err)
	}
	return list, nil
}

// SetCheckKey is PATCH /v1/checks/{id} with {"key": key}.
func (c *Client) SetCheckKey(ctx context.Context, id, key string) error {
	_, err := c.Do(ctx, http.MethodPatch, "/v1/checks/"+url.PathEscape(id), map[string]string{"key": key}, nil, true)
	return err
}

// Plan is POST /v1/checks/plan, which has no side effects.
func (c *Client) Plan(ctx context.Context, req PlanRequest) (*Plan, error) {
	if req.Checks == nil {
		req.Checks = []CheckSpec{}
	}
	var out Plan
	if _, err := c.Do(ctx, http.MethodPost, "/v1/checks/plan", req, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutCheck is PUT /v1/checks/by-key/{key}. created is true on 201.
func (c *Client) PutCheck(ctx context.Context, spec CheckSpec) (chk *Check, created bool, err error) {
	var out Check
	status, err := c.Do(ctx, http.MethodPut, "/v1/checks/by-key/"+url.PathEscape(spec.Key), spec, &out, true)
	if err != nil {
		return nil, false, err
	}
	return &out, status == http.StatusCreated, nil
}

// DeleteCheckByKey is DELETE /v1/checks/by-key/{key}.
func (c *Client) DeleteCheckByKey(ctx context.Context, key string) error {
	_, err := c.Do(ctx, http.MethodDelete, "/v1/checks/by-key/"+url.PathEscape(key), nil, nil, true)
	return err
}

// CreateMeasurement is POST /v1/measurements. It is never retried: a retry
// could start, and bill, a second measurement.
func (c *Client) CreateMeasurement(ctx context.Context, req MeasurementRequest) (*MeasurementCreated, error) {
	var out MeasurementCreated
	if _, err := c.Do(ctx, http.MethodPost, "/v1/measurements", req, &out, false); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetMeasurement is GET /v1/measurements/{id}?wait=N (N in 0..25).
func (c *Client) GetMeasurement(ctx context.Context, id string, wait int) (*Measurement, json.RawMessage, error) {
	p := "/v1/measurements/" + url.PathEscape(id)
	if wait > 0 {
		p += "?wait=" + strconv.Itoa(min(wait, 25))
	}
	var raw json.RawMessage
	if _, err := c.Do(ctx, http.MethodGet, p, nil, &raw, true); err != nil {
		return nil, nil, err
	}
	var m Measurement
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("GET /v1/measurements/%s: decoding answer: %w", id, err)
	}
	return &m, raw, nil
}
