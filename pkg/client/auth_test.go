package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ycyun/syno-cli/pkg/client"
)

func TestClient_2FA_WithOTPProvider(t *testing.T) {
	var loginAttempts int
	var receivedOTP string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/webapi/query.cgi" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"SYNO.API.Auth": client.API{
						MaxVersion: 6,
						Path:       "entry.cgi",
					},
				},
				"success": true,
			})
			return
		}

		if r.URL.Path == "/webapi/entry.cgi/SYNO.API.Auth" {
			_ = r.ParseForm()
			method := r.FormValue("method")
			if method == "login" {
				loginAttempts++
				otpCode := r.FormValue("otp_code")
				if otpCode == "" {
					// Challenge with 2FA (DSM 7.2.2 format)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{
						"error": {
							"code": 403,
							"errors": {
								"token": "dsm7_test_token_xyz"
							}
						},
						"success": false
					}`))
					return
				}

				receivedOTP = otpCode
				if otpCode == "123456" {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{
						"data": {
							"sid": "test_sid_12345"
						},
						"success": true
					}`))
					return
				}

				// Invalid OTP
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{
					"error": {
						"code": 404
					},
					"success": false
				}`))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	var providerCalled bool
	var providerToken string

	cl := client.New(client.Config{
		URL:      server.URL,
		User:     "admin",
		Password: "password",
		OTPProvider: func(ctx context.Context, token string) (string, error) {
			providerCalled = true
			providerToken = token
			return "123456", nil
		},
	})

	err := cl.Login(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, loginAttempts)
	assert.True(t, providerCalled)
	assert.Equal(t, "dsm7_test_token_xyz", providerToken)
	assert.Equal(t, "123456", receivedOTP)
	assert.Equal(t, "test_sid_12345", cl.SID())
}

func TestClient_2FA_WithTOTPSecret(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Synology",
		AccountName: "admin",
	})
	require.NoError(t, err)

	secret := key.Secret()
	var loginAttempts int
	var receivedOTP string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/webapi/query.cgi" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"SYNO.API.Auth": client.API{
						MaxVersion: 6,
						Path:       "entry.cgi",
					},
				},
				"success": true,
			})
			return
		}

		if r.URL.Path == "/webapi/entry.cgi/SYNO.API.Auth" {
			_ = r.ParseForm()
			loginAttempts++
			otpCode := r.FormValue("otp_code")
			if otpCode == "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"error":{"code":403,"errors":{"token":"tok123"}},"success":false}`))
				return
			}
			receivedOTP = otpCode
			valid, _ := totp.ValidateCustom(otpCode, secret, time.Now(), totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if valid {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"sid":"totp_sid_valid"},"success":true}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":{"code":404},"success":false}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cl := client.New(client.Config{
		URL:       server.URL,
		User:      "admin",
		Password:  "password",
		OTPSecret: secret,
	})

	err = cl.Login(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, receivedOTP)
	assert.Equal(t, "totp_sid_valid", cl.SID())
}

func TestClient_2FA_InvalidOTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/webapi/query.cgi" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"SYNO.API.Auth": client.API{
						MaxVersion: 6,
						Path:       "entry.cgi",
					},
				},
				"success": true,
			})
			return
		}

		if r.URL.Path == "/webapi/entry.cgi/SYNO.API.Auth" {
			_ = r.ParseForm()
			if r.FormValue("otp_code") == "" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"error":{"code":403,"errors":{"token":"tok"}},"success":false}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":{"code":404},"success":false}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cl := client.New(client.Config{
		URL:      server.URL,
		User:     "admin",
		Password: "password",
		OTP:      "wrong_code",
	})

	err := cl.Login(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestRemoteError_Helpers(t *testing.T) {
	err403 := &client.RemoteError{
		Code:   403,
		Errors: []byte(`{"token":"my_token"}`),
	}
	assert.True(t, err403.Is2FARequired())
	assert.False(t, err403.IsOTPInvalid())
	assert.Equal(t, "my_token", err403.Token())
	assert.Contains(t, err403.Error(), "2-step verification code required")

	err404 := &client.RemoteError{Code: 404}
	assert.False(t, err404.Is2FARequired())
	assert.True(t, err404.IsOTPInvalid())
	assert.Contains(t, err404.Error(), "OTP invalid or expired")
}

func TestClient_Logout(t *testing.T) {
	var logoutCalled bool
	var logoutSID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/webapi/query.cgi" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"SYNO.API.Auth": client.API{
						MaxVersion: 6,
						Path:       "entry.cgi",
					},
				},
				"success": true,
			})
			return
		}

		if r.URL.Path == "/webapi/entry.cgi/SYNO.API.Auth" {
			_ = r.ParseForm()
			method := r.FormValue("method")
			if method == "login" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"data":{"sid":"sid_999"},"success":true}`))
				return
			}
			if method == "logout" {
				logoutCalled = true
				logoutSID = r.FormValue("_sid")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cl := client.New(client.Config{
		URL:      server.URL,
		User:     "admin",
		Password: "password",
	})

	err := cl.Login(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "sid_999", cl.SID())

	err = cl.Logout(context.Background())
	require.NoError(t, err)
	assert.True(t, logoutCalled)
	assert.Equal(t, "sid_999", logoutSID)
	assert.Empty(t, cl.SID())
}

func TestClient_2FA_PersistsSession(t *testing.T) {
	sessionFile := filepath.Join(t.TempDir(), "session")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/webapi/query.cgi" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"SYNO.API.Auth": client.API{MaxVersion: 6, Path: "entry.cgi"}}, "success": true})
			return
		}
		if r.URL.Path == "/webapi/entry.cgi/SYNO.API.Auth" {
			_ = r.ParseForm()
			if r.FormValue("method") == "logout" {
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			if r.FormValue("method") == "login" && r.FormValue("otp_code") == "123456" {
				_, _ = w.Write([]byte(`{"data":{"sid":"persisted_sid"},"success":true}`))
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	first := client.New(client.Config{URL: server.URL, User: "admin", Password: "password", OTP: "123456", SessionFile: sessionFile})
	require.NoError(t, first.Login(context.Background()))
	assert.Equal(t, "persisted_sid", first.SID())

	second := client.New(client.Config{URL: server.URL, SessionFile: sessionFile})
	assert.Equal(t, "persisted_sid", second.SID())
	require.NoError(t, second.Login(context.Background()))
	require.NoError(t, second.Logout(context.Background()))
	assert.NoFileExists(t, sessionFile)
}
