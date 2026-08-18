package management

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// Client talks to a node's management API. It is what cgdnsctl and the drift
// check are built on.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// ClientOptions configures a Client.
type ClientOptions struct {
	// Addr is the node's management endpoint. A bare host:port is assumed to
	// be HTTPS, since that is what any non-loopback listener must be.
	Addr  string
	Token string

	// LocalSocket dials a unix socket instead of the network. The socket
	// carries no token — its mode is the credential — so Token is not required
	// when this is set.
	LocalSocket string

	// CAFile verifies the node's certificate. Nodes are normally issued from a
	// private CA, so this is the usual way to make a connection trusted.
	CAFile string
	// Insecure skips verification entirely. It is a lab convenience and says so
	// loudly at the call site; a management plane whose certificate is not
	// checked can be impersonated, and it carries the credential in a header.
	Insecure bool

	Timeout time.Duration
}

// NewClient builds an API client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}

	if opts.LocalSocket != "" {
		// The host in the URL is a formality: the transport ignores it and
		// dials the socket. Plain HTTP, because there is no network hop to
		// protect and the socket's mode already decides who may speak.
		base, err := url.Parse("http://localhost")
		if err != nil {
			return nil, err
		}
		path := opts.LocalSocket
		return &Client{
			base: base,
			http: &http.Client{
				Timeout: opts.Timeout,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						var d net.Dialer
						return d.DialContext(ctx, "unix", path)
					},
				},
			},
		}, nil
	}

	if opts.Addr == "" {
		return nil, errors.New("management: a node address is required")
	}
	if opts.Token == "" {
		return nil, errors.New("management: an API token is required")
	}

	raw := opts.Addr
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	base, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("management: parsing node address %q: %w", opts.Addr, err)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("management: node address %q has no host", opts.Addr)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case opts.CAFile != "":
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("management: reading CA %s: %w", opts.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("management: %s contains no certificates", opts.CAFile)
		}
		tlsCfg.RootCAs = pool
	case opts.Insecure:
		tlsCfg.InsecureSkipVerify = true
	}

	return &Client{
		base:  base,
		token: opts.Token,
		http: &http.Client{
			Timeout:   opts.Timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// Addr reports the endpoint this client talks to.
func (c *Client) Addr() string { return c.base.String() }

// do performs one request and decodes the reply into out.
func (c *Client) do(method, path string, body []byte, out any) error {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, u.String(), rdr)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, u.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{Status: resp.StatusCode}
		var e ErrorResponse
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			apiErr.Message = e.Error
		} else {
			apiErr.Message = strings.TrimSpace(string(raw))
		}
		return apiErr
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding response from %s: %w", u.Redacted(), err)
	}
	return nil
}

// Status fetches the node's status.
func (c *Client) Status() (Status, error) {
	var s Status
	err := c.do(http.MethodGet, "/api/v1/status", nil, &s)
	return s, err
}

// Records fetches the raw store dump.
func (c *Client) Records() (RecordsResponse, error) {
	var r RecordsResponse
	err := c.do(http.MethodGet, "/api/v1/records", nil, &r)
	return r, err
}

// List fetches every record of a kind.
func (c *Client) List(kind control.RecordKind) ([]json.RawMessage, error) {
	seg, err := pathFor(kind)
	if err != nil {
		return nil, err
	}
	var resp ListResponse
	if err := c.do(http.MethodGet, "/api/v1/"+seg, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

// Get fetches one record.
func (c *Client) Get(kind control.RecordKind, key string) (json.RawMessage, error) {
	seg, err := pathFor(kind)
	if err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.do(http.MethodGet, "/api/v1/"+seg+"/"+key, nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// Put stores a record, letting the server derive the key from the payload.
func (c *Client) Put(kind control.RecordKind, payload []byte) (WriteResponse, error) {
	seg, err := pathFor(kind)
	if err != nil {
		return WriteResponse{}, err
	}
	var resp WriteResponse
	err = c.do(http.MethodPost, "/api/v1/"+seg, payload, &resp)
	return resp, err
}

// Delete tombstones a record.
func (c *Client) Delete(kind control.RecordKind, key string) (DeleteResponse, error) {
	seg, err := pathFor(kind)
	if err != nil {
		return DeleteResponse{}, err
	}
	var resp DeleteResponse
	err = c.do(http.MethodDelete, "/api/v1/"+seg+"/"+key, nil, &resp)
	return resp, err
}

// Tokens lists the node's API tokens.
func (c *Client) Tokens() ([]Token, error) {
	var resp TokenListResponse
	if err := c.do(http.MethodGet, "/api/v1/tokens", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Tokens, nil
}

// CreateToken mints a token. The secret it returns is not recoverable later.
func (c *Client) CreateToken(req TokenRequest) (MintedToken, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return MintedToken{}, err
	}
	var out MintedToken
	err = c.do(http.MethodPost, "/api/v1/tokens", body, &out)
	return out, err
}

// Users lists operator accounts.
func (c *Client) Users() ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := c.do(http.MethodGet, "/api/v1/users", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// CreateUser adds an operator account.
func (c *Client) CreateUser(name, password string, scopes []Scope) error {
	body, err := json.Marshal(map[string]any{"name": name, "password": password, "scopes": scopes})
	if err != nil {
		return err
	}
	return c.do(http.MethodPost, "/api/v1/users", body, nil)
}

// DeleteUser removes an operator account.
func (c *Client) DeleteUser(name string) error {
	return c.do(http.MethodDelete, "/api/v1/users/"+name, nil, nil)
}

// RevokeToken deletes a token.
func (c *Client) RevokeToken(id string) error {
	return c.do(http.MethodDelete, "/api/v1/tokens/"+id, nil, nil)
}
