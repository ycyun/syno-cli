package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pquerna/otp/totp"
)

const (
	EnvURL         = "SYNOLOGY_URL"
	EnvUser        = "SYNOLOGY_USER"
	EnvPass        = "SYNOLOGY_PASSWORD" //nolint:gosec
	EnvOTP         = "SYNOLOGY_OTP"
	EnvOTPSecret   = "SYNOLOGY_OTP_SECRET" //nolint:gosec
	EnvSession     = "SYNOLOGY_SESSION"
	EnvSessionFile = "SYNOLOGY_SESSION_FILE"
)

const DefaultTimeout = 30 * time.Second

var ErrBadStatus = errors.New("bad response status")

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type HTTPClientFunc func(req *http.Request) (*http.Response, error)

func (hf HTTPClientFunc) Do(req *http.Request) (*http.Response, error) {
	return hf(req)
}

// OTPProvider is called when Synology challenges for two-factor authentication (OTP).
// token is the temporary 2FA token returned by DSM if present.
type OTPProvider func(ctx context.Context, token string) (string, error)

type Config struct {
	Client      HTTPClient  // HTTP client to perform requests, default is new HTTP client. Client MUST support cookies. Keep it nil for most cases is a good idea.
	User        string      // User name
	Password    string      // User password
	URL         string      // Synology url, default is http://localhost:5000
	OTP         string      // 6-digit OTP code (optional)
	OTPSecret   string      // Base32 TOTP secret for automatic OTP code generation (optional)
	OTPProvider OTPProvider // Callback to obtain OTP when 2FA is required (optional)
	Session     string      // Synology session name, default is "FileStation"
	SessionFile string      // Optional file to persist the authenticated session ID.
}

// Default client based on env variables.
func Default() *Client {
	return New(FromEnv(nil))
}

// FromEnv creates config based on standard environment variables. If envFunc not defined,
// os.Getenv will be used.
func FromEnv(envFunc func(string) string) Config {
	if envFunc == nil {
		envFunc = os.Getenv
	}

	getAny := func(keys ...string) string {
		for _, k := range keys {
			if v := envFunc(k); v != "" {
				return v
			}
		}
		return ""
	}

	return Config{
		User:        getAny(EnvUser, "NAS_USER"),
		Password:    getAny(EnvPass, "NAS_PASSWORD", "NAS_PASS"),
		URL:         getAny(EnvURL, "NAS_URL"),
		OTP:         getAny(EnvOTP, "NAS_OTP", "OTP_CODE", "OTP"),
		OTPSecret:   getAny(EnvOTPSecret, "NAS_OTP_SECRET", "OTP_SECRET"),
		Session:     getAny(EnvSession, "NAS_SESSION"),
		SessionFile: getAny(EnvSessionFile, "NAS_SESSION_FILE"),
	}
}

// New instance of Synology API client.
func New(cfg Config) *Client {
	if cfg.Client == nil {
		jar, err := cookiejar.New(nil)
		if err != nil {
			panic(err) // CAN NOT happen at go 1.23
		}
		cfg.Client = &http.Client{
			Jar:     jar,
			Timeout: DefaultTimeout,
		}
	}
	if cfg.URL == "" {
		cfg.URL = "http://localhost:5000"
	} else {
		cfg.URL = strings.TrimRight(cfg.URL, "/")
	}
	if cfg.Session == "" {
		cfg.Session = "FileStation"
	}

	cl := &Client{
		client:      cfg.Client,
		user:        cfg.User,
		password:    cfg.Password,
		baseURL:     cfg.URL,
		otp:         cfg.OTP,
		otpSecret:   cfg.OTPSecret,
		otpProvider: cfg.OTPProvider,
		session:     cfg.Session,
		sessionFile: strings.TrimSpace(cfg.SessionFile),
	}
	if cl.sessionFile != "" {
		if data, err := os.ReadFile(cl.sessionFile); err == nil {
			if sid := strings.TrimSpace(string(data)); sid != "" {
				cl.sid = sid
				cl.authorized.Store(true)
			}
		}
	}
	return cl
}

type Client struct {
	client      HTTPClient
	user        string
	password    string
	baseURL     string
	otp         string
	otpSecret   string
	otpProvider OTPProvider
	session     string
	sessionFile string
	sid         string
	sidLock     sync.RWMutex
	authorized  atomic.Bool
	authLock    sync.Mutex
	versionLock sync.Mutex
	versions    map[string]API
}

// SID returns the current session ID if logged in.
func (cl *Client) SID() string {
	cl.sidLock.RLock()
	defer cl.sidLock.RUnlock()
	return cl.sid
}

// SetOTP updates the OTP code.
func (cl *Client) SetOTP(otp string) {
	cl.otp = otp
}

// SetOTPSecret updates the Base32 TOTP secret.
func (cl *Client) SetOTPSecret(secret string) {
	cl.otpSecret = secret
}

// SetOTPProvider updates the OTP provider callback.
func (cl *Client) SetOTPProvider(provider OTPProvider) {
	cl.otpProvider = provider
}

// WithClient returns copy of Synology client with custom HTTP client.
func (cl *Client) WithClient(client HTTPClient) *Client {
	cl.versionLock.Lock()
	defer cl.versionLock.Unlock()
	cl.authLock.Lock()
	defer cl.authLock.Unlock()

	return &Client{
		client:      client,
		user:        cl.user,
		password:    cl.password,
		baseURL:     cl.baseURL,
		otp:         cl.otp,
		otpSecret:   cl.otpSecret,
		otpProvider: cl.otpProvider,
		session:     cl.session,
		sessionFile: cl.sessionFile,
		versions:    cl.versions,
	}
}

// APIVersion returns max version for specific API. It queries Synology for all APIs and caches result.
func (cl *Client) APIVersion(ctx context.Context, apiName string) (API, error) {
	if m := cl.versions; m != nil {
		return m[apiName], nil
	}
	cl.versionLock.Lock()
	defer cl.versionLock.Unlock()
	if m := cl.versions; m != nil {
		return m[apiName], nil
	}

	err := cl.doPost(ctx, "/webapi/query.cgi", nil, map[string]interface{}{
		"method":  "query",
		"api":     "SYNO.API.Info",
		"version": 1,
	}, &cl.versions)
	if err != nil {
		return API{}, fmt.Errorf("invoke api: %w", err)
	}

	return cl.versions[apiName], nil
}

// Login to Synology and get token. Token will be cached. If token already obtained, API call will not be executed.
// If 2FA is required, it will automatically handle OTP via configured OTP, TOTP secret, or OTPProvider callback.
func (cl *Client) Login(ctx context.Context) error {
	if cl.authorized.Load() {
		return nil
	}

	cl.authLock.Lock()
	defer cl.authLock.Unlock()
	if cl.authorized.Load() {
		return nil
	}

	session := cl.session
	if session == "" {
		session = "FileStation"
	}

	performLogin := func(otpCode string) (*http.Response, error) {
		slog.Debug("attempting Synology login", "user", cl.user, "session", session, "with_otp", otpCode != "")
		params := []field{
			{Name: "enable_syno_token", Value: "no"},
			{Name: "account", Value: cl.user},
			{Name: "passwd", Value: cl.password},
			{Name: "session", Value: session},
			{Name: "format", Value: "cookie"},
		}
		if otpCode != "" {
			params = append(params, field{Name: "otp_code", Value: otpCode})
		}
		return cl.directCall(ctx, "SYNO.API.Auth", "login", params)
	}

	initialOTP := cl.otp
	if initialOTP == "" && cl.otpSecret != "" {
		code, err := totp.GenerateCode(cl.otpSecret, time.Now())
		if err == nil {
			initialOTP = code
			slog.Debug("generated OTP from secret for login", "user", cl.user)
		}
	}

	res, err := performLogin(initialOTP)
	if err != nil {
		var remoteErr *RemoteError
		if errors.As(err, &remoteErr) && remoteErr.Is2FARequired() {
			otpToken := remoteErr.Token()
			slog.Debug("2FA challenge detected from Synology DSM", "code", remoteErr.Code, "token", otpToken)
			var otpCode string

			if initialOTP == "" && cl.otpSecret != "" {
				code, totpErr := totp.GenerateCode(cl.otpSecret, time.Now())
				if totpErr != nil {
					return fmt.Errorf("generate TOTP code from secret: %w", totpErr)
				}
				otpCode = code
				slog.Debug("generated OTP from secret for 2FA challenge")
			} else if cl.otpProvider != nil {
				slog.Debug("prompting OTP via provider")
				code, provErr := cl.otpProvider(ctx, otpToken)
				if provErr != nil {
					return fmt.Errorf("obtain OTP code: %w", provErr)
				}
				otpCode = strings.TrimSpace(code)
			}

			if otpCode == "" {
				return fmt.Errorf("2-step verification (2FA) is required for user %q, but no OTP code was provided: %w", cl.user, err)
			}

			res, err = performLogin(otpCode)
			if err != nil {
				return fmt.Errorf("2FA login failed: %w", err)
			}
		} else {
			return fmt.Errorf("invoke api: %w", err)
		}
	}

	defer res.Body.Close()

	var loginData struct {
		Data struct {
			SID string `json:"sid"`
		} `json:"data"`
	}
	bodyBytes, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(bodyBytes, &loginData); err == nil && loginData.Data.SID != "" {
		cl.sidLock.Lock()
		cl.sid = loginData.Data.SID
		cl.sidLock.Unlock()
		if cl.sessionFile != "" {
			if dir := filepath.Dir(cl.sessionFile); dir != "." {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					return fmt.Errorf("create session directory: %w", err)
				}
			}
			if err := os.WriteFile(cl.sessionFile, []byte(loginData.Data.SID+"\n"), 0o600); err != nil {
				return fmt.Errorf("save session: %w", err)
			}
		}
	}

	cl.authorized.Store(true)
	return nil
}

// Logout from Synology and invalidate session.
func (cl *Client) Logout(ctx context.Context) error {
	cl.authLock.Lock()
	defer cl.authLock.Unlock()

	session := cl.session
	if session == "" {
		session = "FileStation"
	}

	params := []field{
		{Name: "session", Value: session},
	}
	cl.sidLock.RLock()
	sid := cl.sid
	cl.sidLock.RUnlock()
	if sid != "" {
		params = append(params, field{Name: "_sid", Value: sid})
	}

	res, err := cl.directCall(ctx, "SYNO.API.Auth", "logout", params)
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)

	cl.sidLock.Lock()
	cl.sid = ""
	cl.sidLock.Unlock()
	cl.authorized.Store(false)
	if cl.sessionFile != "" {
		if err := os.Remove(cl.sessionFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove saved session: %w", err)
		}
	}
	return nil
}

// DownloadStation API
func (cl *Client) DownloadStation() *DownloadStation {
	return &DownloadStation{cl: cl}
}

func (cl *Client) callAPI(ctx context.Context, apiName, method string, params map[string]interface{}, out interface{}) error {
	info, err := cl.APIVersion(ctx, apiName)
	if err != nil {
		return fmt.Errorf("get API %s version: %w", apiName, err)
	}

	var queryParams = map[string]interface{}{
		"method":  method,
		"api":     apiName,
		"version": info.MaxVersion,
	}
	if sid := cl.SID(); sid != "" {
		queryParams["_sid"] = sid
	}

	// if it's not upload, we can merge transport params into payload
	if !needStreaming(params) {
		if params == nil {
			params = queryParams
		} else {
			for k, v := range queryParams {
				params[k] = v
			}
			queryParams = nil
		}
	}

	return cl.doPost(ctx, "/webapi/"+info.Path, queryParams, params, out)
}

// deprecated, use directCall instead
func (cl *Client) doPost(ctx context.Context, path string, queryParams map[string]interface{}, params map[string]interface{}, out interface{}) error {
	var contentType string
	var content io.ReadCloser
	if needStreaming(params) {
		contentType, content = streamData(mapToFields(params))
	} else {
		contentType, content = plainData(mapToFields(params))
	}
	defer content.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.baseURL+path+"?"+joinParams(mapToFields(queryParams)), content)
	if err != nil {
		return fmt.Errorf("prepare request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	res, err := cl.client.Do(req)
	if err != nil {
		return fmt.Errorf("execute request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %w", res.StatusCode, ErrBadStatus)
	}

	var rawResponse apiResponse

	err = json.NewDecoder(res.Body).Decode(&rawResponse)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if err := rawResponse.Error; err != nil {
		return fmt.Errorf("response: %w", err)
	}
	err = json.Unmarshal(rawResponse.RawData, out)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	return nil
}

func (cl *Client) directCall(ctx context.Context, apiName string, method string, params []field) (*http.Response, error) {
	info, err := cl.APIVersion(ctx, apiName)
	if err != nil {
		return nil, fmt.Errorf("get API %s version: %w", apiName, err)
	}

	params = append([]field{
		{Name: "api", Value: apiName},
		{Name: "version", Value: info.MaxVersion},
		{Name: "method", Value: method},
	}, params...)
	if sid := cl.SID(); sid != "" {
		params = append(params, field{Name: "_sid", Value: sid})
	}
	requestURL := cl.baseURL + "/webapi/" + info.Path + "/" + apiName

	var contentType string
	var content io.ReadCloser
	if needStreamingIter(params) {
		contentType, content = streamData(params)
	} else {
		contentType, content = plainData(params)
	}
	defer content.Close()

	slog.Debug("API request prepared", "url", requestURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, content)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	res, err := cl.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call API: %w", err)
	}
	defer res.Body.Close()

	//nolint:mnd
	if res.StatusCode/100 != 2 {
		_ = res.Body.Close()
		return nil, fmt.Errorf("status %d: %w", res.StatusCode, ErrBadStatus)
	}

	// try to parse body as API response
	var buffer bytes.Buffer
	if err := asAPIError(io.TeeReader(res.Body, &buffer)); err != nil {
		_ = res.Body.Close()
		return nil, fmt.Errorf("application API error: %w", err)
	}
	res.Body = &readCloser{
		Reader: io.MultiReader(&buffer, res.Body),
		Closer: res.Body,
	}

	return res, nil
}

func asAPIError(data io.Reader) error {
	var rawResponse apiResponse

	err := json.NewDecoder(data).Decode(&rawResponse)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if !rawResponse.Success {
		return rawResponse.Error
	}
	return nil
}

func plainData(params []field) (string, io.ReadCloser) {
	return "application/x-www-form-urlencoded", io.NopCloser(strings.NewReader(joinParams(params)))
}

func streamData(fields []field) (string, io.ReadCloser) {
	reader, writer := io.Pipe()
	mp := multipart.NewWriter(writer)

	go func() {
		err := streamMultipart(fields, mp)
		if err == nil {
			err = mp.Close()
		}
		_ = writer.CloseWithError(err)
	}()
	return mp.FormDataContentType(), reader
}

func joinParams(params []field) string {
	var buffer bytes.Buffer
	for _, field := range params {
		if buffer.Len() > 0 {
			buffer.WriteRune('&')
		}
		buffer.WriteString(url.QueryEscape(field.Name))
		buffer.WriteRune('=')
		if v, ok := field.Value.([]byte); ok {
			buffer.WriteString(url.QueryEscape(string(v)))
		} else {
			buffer.WriteString(url.QueryEscape(fmt.Sprint(field.Value)))
		}
	}
	return buffer.String()
}

type field struct {
	Name  string
	Value interface{} // Reader, fileAttachment, []byte, string, else (Sprint'able)
}

func streamMultipart(fields []field, w *multipart.Writer) error {
	for _, field := range fields {
		var dest io.Writer
		var source io.Reader
		switch v := field.Value.(type) {
		case io.Reader:
			out, err := w.CreateFormField(field.Name)
			if err != nil {
				return fmt.Errorf("create part for %s: %w", field.Name, err)
			}
			dest = out
			source = v
		case fileAttachment:
			out, err := w.CreateFormFile(field.Name, v.FileName)
			if err != nil {
				return fmt.Errorf("create part for %s: %w", field.Name, err)
			}
			dest = out
			source = v.Reader
		case []byte:
			out, err := w.CreateFormField(field.Name)
			if err != nil {
				return fmt.Errorf("create part for %s: %w", field.Name, err)
			}
			dest = out
			source = bytes.NewReader(v)
		case string:
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", `form-data; name=`+strconv.Quote(field.Name))

			out, err := w.CreatePart(h)
			if err != nil {
				return fmt.Errorf("create part for %s: %w", field.Name, err)
			}
			dest = out
			source = strings.NewReader(v)
		default:
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", `form-data; name=`+strconv.Quote(field.Name))
			out, err := w.CreatePart(h)
			if err != nil {
				return fmt.Errorf("create part for %s: %w", field.Name, err)
			}
			dest = out
			source = strings.NewReader(fmt.Sprint(v))
		}
		if _, err := io.Copy(dest, source); err != nil {
			return fmt.Errorf("copy content for part %s: %w", field.Name, err)
		}
	}
	return nil
}

// deprecated
func needStreaming(params map[string]interface{}) bool {
	for _, v := range params {
		switch v.(type) {
		case io.Reader, *fileAttachment, fileAttachment:
			return true
		}
	}
	return false
}

func needStreamingIter(params []field) bool {
	for _, f := range params {
		switch f.Value.(type) {
		case io.Reader, *fileAttachment, fileAttachment:
			return true
		}
	}
	return false
}

type fileAttachment struct {
	FileName string
	Reader   io.Reader
}

type apiResponse struct {
	Success bool            `json:"success"`
	Error   *RemoteError    `json:"error,omitempty"`
	RawData json.RawMessage `json:"data"`
}

type API struct {
	MaxVersion int64  `json:"maxVersion"`
	Path       string `json:"path"`
}

type RemoteError struct {
	Code   int64           `json:"code"`
	Errors json.RawMessage `json:"errors,omitempty"`
}

type AuthErrorDetails struct {
	Token string `json:"token"`
}

func (e *RemoteError) Token() string {
	if len(e.Errors) == 0 {
		return ""
	}
	var details AuthErrorDetails
	if err := json.Unmarshal(e.Errors, &details); err == nil && details.Token != "" {
		return details.Token
	}
	return ""
}

func (e *RemoteError) Is2FARequired() bool {
	if e == nil {
		return false
	}
	if e.Code == 403 || e.Code == 406 {
		return true
	}
	return e.Token() != ""
}

func (e *RemoteError) IsOTPInvalid() bool {
	if e == nil {
		return false
	}
	return e.Code == 404
}

func (e *RemoteError) Error() string {
	var desc string
	switch e.Code {
	case 400:
		desc = "no such account or incorrect password"
	case 401:
		desc = "account disabled"
	case 402:
		desc = "permission denied"
	case 403:
		desc = "2-step verification code required"
	case 404:
		desc = "failed to authenticate 2-step verification code (OTP invalid or expired)"
	case 406:
		desc = "OTP authentication enforced"
	case 407:
		desc = "IP source blocked due to too many failed login attempts"
	}
	if desc != "" {
		return fmt.Sprintf("API error code %d (%s)", e.Code, desc)
	}
	return "API error code: " + strconv.FormatInt(e.Code, 10)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// deprecated, used for compatibility only
func mapToFields(fields map[string]interface{}) []field {
	l := make([]field, 0, len(fields))
	for k, v := range fields {
		l = append(l, field{
			Name:  k,
			Value: v,
		})
	}
	return l
}
