package mafate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpClient is the internal HTTP transport. It is not exported; callers use
// the high-level methods on Client instead.
type httpClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func newHTTPClient(baseURL, apiKey string, transport http.RoundTripper, timeout time.Duration) *httpClient {
	return &httpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

// buildURL constructs the full request URL, appending any query parameters.
func (c *httpClient) buildURL(path string, params map[string]string) (string, error) {
	full := c.baseURL + path
	if len(params) == 0 {
		return full, nil
	}
	u, err := url.Parse(full)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// do executes an HTTP request and decodes the JSON response into out.
// If out is nil the response body is discarded (used for 204 endpoints).
func (c *httpClient) do(ctx context.Context, method, path string, params map[string]string, body, out interface{}) error {
	rawURL, err := c.buildURL(path, params)
	if err != nil {
		return &MafateError{Message: fmt.Sprintf("build url: %s", err)}
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return &MafateError{Message: fmt.Sprintf("marshal request: %s", err)}
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return &MafateError{Message: fmt.Sprintf("create request: %s", err)}
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &MafateError{Message: fmt.Sprintf("execute request: %s", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.decodeError(resp)
	}

	if resp.StatusCode == http.StatusNoContent || out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return &MafateError{Message: fmt.Sprintf("decode response: %s", err)}
	}
	return nil
}

// decodeError reads the response body and attempts to parse an RFC 7807
// problem detail. Falls back to the HTTP status text on parse failure.
func (c *httpClient) decodeError(resp *http.Response) error {
	apiErr := &ApiError{
		Status: resp.StatusCode,
		Title:  resp.Status,
	}

	raw, err := io.ReadAll(resp.Body)
	if err == nil && len(raw) > 0 {
		var pd problemDetail
		if json.Unmarshal(raw, &pd) == nil {
			if pd.Title != "" {
				apiErr.Title = pd.Title
			}
			apiErr.Detail = pd.Detail
		}
	}

	return apiErr
}

// get performs a GET request with optional query parameters.
func (c *httpClient) get(ctx context.Context, path string, params map[string]string, out interface{}) error {
	return c.do(ctx, http.MethodGet, path, params, nil, out)
}

// post performs a POST request with an optional JSON body.
func (c *httpClient) post(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPost, path, nil, body, out)
}

// patch performs a PATCH request with an optional JSON body.
func (c *httpClient) patch(ctx context.Context, path string, body, out interface{}) error {
	return c.do(ctx, http.MethodPatch, path, nil, body, out)
}

// delete performs a DELETE request (no response body expected).
func (c *httpClient) delete(ctx context.Context, path string) error {
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}
