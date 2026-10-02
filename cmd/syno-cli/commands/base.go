package commands

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ycyun/syno-cli/pkg/client"
)

type SynoClient struct {
	User            string        `long:"user" env:"USER" description:"Synology username"`
	Password        string        `long:"password" env:"PASSWORD" description:"Synology password"`
	URL             string        `long:"url" env:"URL" description:"Synology URL" default:"http://localhost:5000"`
	Insecure        bool          `long:"insecure" env:"INSECURE" description:"Disable TLS (HTTPS) verification"`
	Timeout         time.Duration `long:"timeout" env:"TIMEOUT" description:"Default timeout" default:"30s"`
	OTP             string        `long:"otp" env:"OTP" description:"Synology 2FA OTP code"`
	OTPSecret       string        `long:"otp-secret" env:"OTP_SECRET" description:"Synology 2FA TOTP secret key for automatic code generation"`
	Session         string        `long:"session" env:"SESSION" description:"Synology session name" default:"FileStation"`
	SessionFile     string        `long:"session-file" env:"SESSION_FILE" description:"Persist Synology session ID in this file"`
	DeviceToken     string        `long:"device-token" env:"DEVICE_TOKEN" description:"Synology device ID to skip OTP"`
	DeviceName      string        `long:"device-name" env:"DEVICE_NAME" description:"Synology trusted device name" default:"syno-cli"`
	DeviceTokenFile string        `long:"device-token-file" env:"DEVICE_TOKEN_FILE" description:"Persist Synology device ID in this file"`
	NoDeviceToken   bool          `long:"no-device-token" env:"NO_DEVICE_TOKEN" description:"Disable trusted device token support"`
	Debug           bool          `long:"debug" env:"DEBUG" description:"Enable debug logging"`
	Verbose         bool          `long:"verbose" env:"VERBOSE" description:"Enable verbose logging"`
}

func (sc SynoClient) Client() *client.Client {
	if sc.Debug || sc.Verbose {
		lvl := new(slog.LevelVar)
		lvl.Set(slog.LevelDebug)
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: lvl,
		}))
		slog.SetDefault(logger)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err) // impossible
	}
	var httpClient = &http.Client{
		Jar:     jar,
		Timeout: sc.Timeout,
	}
	if sc.Insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	var otpProvider client.OTPProvider
	if sc.OTP == "" && sc.OTPSecret == "" {
		otpProvider = func(ctx context.Context, token string) (string, error) {
			fmt.Fprintln(os.Stderr, "🔐 2FA detected. Please enter OTP.")
			fmt.Fprint(os.Stderr, "OTP code: ")
			reader := bufio.NewReader(os.Stdin)
			text, err := reader.ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			return strings.TrimSpace(text), nil
		}
	}
	if strings.TrimSpace(sc.SessionFile) == "" {
		sc.SessionFile = defaultSessionFile()
	}
	if strings.TrimSpace(sc.DeviceTokenFile) == "" {
		sc.DeviceTokenFile = sc.SessionFile + ".device-token"
	}

	return client.New(client.Config{
		Client:             httpClient,
		User:               sc.User,
		Password:           sc.Password,
		URL:                sc.URL,
		OTP:                sc.OTP,
		OTPSecret:          sc.OTPSecret,
		OTPProvider:        otpProvider,
		Session:            sc.Session,
		SessionFile:        sc.SessionFile,
		DeviceToken:        sc.DeviceToken,
		DeviceName:         sc.DeviceName,
		DeviceTokenFile:    sc.DeviceTokenFile,
		DisableDeviceToken: sc.NoDeviceToken,
	})
}

func defaultSessionFile() string {
	if configDir, err := os.UserConfigDir(); err == nil {
		path := filepath.Join(configDir, "syno-cli")
		if err := os.MkdirAll(path, 0o700); err == nil {
			return filepath.Join(path, "session")
		}
	}

	if executable, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(executable), ".syno-cli-session")
	}
	return ".syno-cli-session"
}

const (
	fmtJSON  = "json"
	fmtTable = "table"
)

type Logging struct {
	Debug   bool `long:"debug" env:"DEBUG" description:"Enable debug logging"`
	Verbose bool `short:"v" long:"verbose" env:"VERBOSE" description:"Enable verbose logging"`
}

func (l *Logging) SetupLogging() {
	lvl := new(slog.LevelVar)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	}))
	if l.Debug || l.Verbose {
		lvl.Set(slog.LevelDebug)
	} else {
		lvl.Set(slog.LevelInfo)
	}

	slog.SetDefault(logger)
}
