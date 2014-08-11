package opbeat

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Any logger must implement Printf.
type Logger interface {
	Printf(string, ...interface{})
}

type Client struct {
	URL        *url.URL
	config     *ClientConfig
	httpClient *http.Client
}

type Stacktrace struct {
	Frames []Frame `json:"frames"`
}

type Frame struct {
	AbsFilename string `json:"abs_path"`
	Filename    string `json:"filename"`
	LineNo      int    `json:"lineno"`
	Function    string `json:"function"`
	InApp       bool   `json:"in_app"`
}

type User struct {
	Id              string `json:"id"`
	Email           string `json:"email"`
	Username        string `json:"username"`
	IsAuthenticated bool   `json:"is_authenticated"`
}

type Http struct {
	Url     string `json:"url"`
	Method  string `json:"method"`
	Headers map[string]string
}

// Extract interesting information from a regular http.Request struct
// and return a Http object
func NewHttpFromRequest(r *http.Request) *Http {
	// Multiple values for the same key will
	// result in the same key being included multiple
	// times according to http://golang.org/src/pkg/net/http/header.go?#L145
	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = v[len(v)-1] // Just take the last one for now
	}

	scheme := ""
	if r.TLS != nil {
		scheme = "https"
	} else {
		scheme = "http"
	}

	fullUrl := scheme + "://" + r.Host + r.URL.String()

	return &Http{
		Url:     fullUrl,
		Method:  r.Method,
		Headers: headers,
	}
}

type EventOptions struct {
	Extra *map[string]interface{} `json:"extra"`
	User  *User                   `json:"user"`
	Http  *Http                   `json:"http"`
}

type Event struct {
	Message    string                  `json:"message"`
	Timestamp  string                  `json:"timestamp"`
	Level      string                  `json:"level"`
	Logger     string                  `json:"logger"`
	Culprit    string                  `json:"culprit"`
	Extra      *map[string]interface{} `json:"extra"`
	User       *User                   `json:"user"`
	Http       *Http                   `json:"http"`
	Stacktrace *Stacktrace             `json:"stacktrace"`
	Machine    map[string]string       `json:"machine"`
}

// An iso8601 timestamp without the timezone.
const iso8601 = "2006-01-02T15:04:05"

const defaultHost = "opbeat.com"
const defaultTimeout = 3 * time.Second

type ClientConfig struct {
	OrganizationId string
	AppId          string
	SecretToken    string
	Host           string
	SkipVerify     bool
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	Logger
}

func fillConfig(config *ClientConfig) error {
	if len(config.OrganizationId) == 0 {
		config.OrganizationId = os.Getenv("OPBEAT_ORGANIZATION_ID")
	}

	if len(config.AppId) == 0 {
		config.OrganizationId = os.Getenv("OPBEAT_APP_ID")
	}

	if len(config.SecretToken) == 0 {
		config.SecretToken = os.Getenv("OPBEAT_SECRET_TOKEN")
	}

	if len(config.Host) == 0 {
		config.Host = os.Getenv("OPBEAT_HOST")
		if len(config.Host) == 0 {
			config.Host = defaultHost
		}
	}

	if config.ConnectTimeout < 1 {
		connectTimeout := os.Getenv("OPBEAT_CONNECT_TIMEOUT")
		if len(connectTimeout) != 0 {
			connectTimeoutSec, err := strconv.Atoi(connectTimeout)
			if err != nil {
				return err
			}
			config.ConnectTimeout = time.Duration(connectTimeoutSec) * time.Second
		} else {
			config.ConnectTimeout = defaultTimeout
		}
	}

	if config.ReadTimeout < 1 {
		readTimeout := os.Getenv("OPBEAT_READ_TIMEOUT")
		if len(readTimeout) != 0 {
			readTimeoutSec, err := strconv.Atoi(readTimeout)
			if err != nil {
				return err
			}
			config.ReadTimeout = time.Duration(readTimeoutSec) * time.Second
		} else {
			config.ReadTimeout = defaultTimeout
		}
	}

	if config.SkipVerify {
		if config.Logger != nil {
			config.Printf("Warning: SkipVerify is true. Remote certificates not be verified")
		}
	}
	return nil
}

func checkConfig(config *ClientConfig) error {
	if len(config.OrganizationId) == 0 {
		return errors.New("Missing OrganizationId. Can be set via environment variable OPBEAT_ORGANIZATION_ID")
	}

	if len(config.AppId) == 0 {
		return errors.New("Missing AppId. Can be set via environment variable OPBEAT_APP_ID")
	}

	if len(config.SecretToken) == 0 {
		return errors.New("Missing SecretToken. Can be set via environment variable OPBEAT_SECRET_TOKEN")
	}
	return nil
}

// NewClientFromEnv reads all configuration from the environement.
// Variables are: OPBEAT_ORGANIZATION_ID, OPBEAT_APP_ID, OPBEAT_SECRET_TOKEN,
// OPBEAT_HOST, OPBEAT_CONNECT_TIMEOUT, OPBEAT_READ_TIMEOUT
func NewClientFromEnv() (client *Client, err error) {
	return NewClient(nil)
}

// NewClient creates a new client. It will attempt to read missing parameters from the environment
func NewClient(config *ClientConfig) (client *Client, err error) {
	err = fillConfig(config)
	if err != nil {
		return nil, err
	}
	if err = checkConfig(config); err != nil {
		return nil, err
	}

	url, _ := url.Parse(fmt.Sprintf(
		"https://%s/api/v1/organizations/%s/apps/%s/errors/",
		config.Host,
		config.OrganizationId,
		config.AppId))

	transport := &transport{
		httpTransport: &http.Transport{
			Dial:            timeoutDialer(config.ConnectTimeout),
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipVerify},
		}, timeout: config.ReadTimeout}
	httpClient := &http.Client{Transport: transport}
	return &Client{URL: url, config: config, httpClient: httpClient}, nil
}

// CaptureMessage sends a message to Opbeat
// It returns nil or any error that occurred.
// `options` allows for additional info to be included.
func (client Client) Capture(ev *Event) (string, error) {
	eventLink, err := client.capture(ev)

	if err != nil {
		return "", err
	}
	return eventLink, nil
}

// CaptureMessage sends a message to Opbeat
// It returns nil or any error that occurred.
// Use `CaptureMessageWithOptions` to include additional info
func (client Client) CaptureMessage(message ...string) (string, error) {
	msg := strings.Join(message, " ")
	ev := Event{Message: msg}
	eventLink, err := client.capture(&ev)
	if err != nil {
		return "", err
	}
	return eventLink, nil
}

// CaptureMessageWithOptions sends a message to Opbeat
// It returns nil or any error that occurred.
// `options` allows for additional info to be included.
func (client Client) CaptureMessageWithOptions(message string, options *EventOptions) (string, error) {
	ev := client.eventWithOptions(options)
	ev.Message = message

	eventLink, err := client.capture(ev)

	if err != nil {
		return "", err
	}
	return eventLink, nil
}

// CaptureError sends a message to Opbeat
// It returns nil or any error that occurred.
func (client Client) CaptureError(err error) (string, error) {
	ev := Event{Message: err.Error()}
	eventLink, opbeatErr := client.capture(&ev)

	if opbeatErr != nil {
		return "", opbeatErr
	}
	return eventLink, nil
}

// CaptureErrorWithOptions sends a message to Opbeat
// It returns nil or any error that occurred.
// `options` allows for additional info to be included.
func (client Client) CaptureErrorWithOptions(err error, options *EventOptions) (string, error) {
	ev := client.eventWithOptions(options)
	ev.Message = err.Error()

	eventLink, opbeatErr := client.capture(ev)

	if opbeatErr != nil {
		return "", opbeatErr
	}
	return eventLink, nil
}

func (client Client) eventWithOptions(options *EventOptions) *Event {
	return &Event{
		Extra: options.Extra,
		User:  options.User,
		Http:  options.Http,
	}
}

// Capture sends the given event to Opbeat.
// Fields which are left blank are populated with default values.
// Expects to be called as the 2nd in the stackstrace in this library.
// E.g. user code calls a method in the library which calls this.
func (client Client) capture(ev *Event) (string, error) {
	// Fill in defaults
	if ev.Level == "" {
		ev.Level = "error"
	}
	if ev.Logger == "" {
		ev.Logger = "root"
	}
	if ev.Timestamp == "" {
		now := time.Now().UTC()
		ev.Timestamp = now.Format(iso8601)
	}

	if ev.Stacktrace == nil {
		ev.Stacktrace = stack(3)
	}

	if ev.Culprit == "" {
		ev.Culprit = fmt.Sprintf("%s in %s", ev.Stacktrace.Frames[0].Filename, ev.Stacktrace.Frames[0].Function)
	}

	if len(ev.Machine) == 0 {
		if hostname, err := os.Hostname(); err == nil {
			ev.Machine = map[string]string{"hostname": hostname}
		}
	}

	client.log("Sending event to Opbeat server: %v", ev.Message)

	buf := new(bytes.Buffer)
	writer := zlib.NewWriter(buf)
	jsonEncoder := json.NewEncoder(writer)

	if err := jsonEncoder.Encode(ev); err != nil {
		return "", err
	}

	err := writer.Close()
	if err != nil {
		return "", err
	}

	eventLink, err := client.send(buf.Bytes())
	if err != nil {
		return "", err
	}

	return eventLink, nil
}

// sends a packet to Opbeat
func (client Client) send(packet []byte) (eventLink string, err error) {
	apiURL := *client.URL
	location := apiURL.String()

	buf := bytes.NewBuffer(packet)
	req, err := http.NewRequest("POST", location, buf)
	if err != nil {
		return "", err
	}

	authHeader := fmt.Sprintf("Bearer %s", client.config.SecretToken)
	req.Header.Add("Authorization", authHeader)
	req.Header.Add("Content-Type", "application/octet-stream")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Accept-Encoding", "identity")

	resp, err := client.httpClient.Do(req)

	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	switch resp.StatusCode {
	case 202:
		if resp.Header["Location"] != nil {
			client.log("Event details at %s", resp.Header["Location"][0])
			return resp.Header["Location"][0], nil
		}
		return "", nil
	default:
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			obErr := fmt.Errorf("While reading response body of failed request: %v", err)
			client.log(obErr.Error())
			return "", obErr
		}

		obErr := fmt.Errorf("Opbeat response %v: %s", resp.Status, string(body[:]))
		client.log(obErr.Error())
		return "", obErr
	}
}

// Useful handler to catch panics further down the handler chain
func OpbeatHandler(client *Client, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				client.CaptureMessageWithOptions(fmt.Sprintf("%v", rec),
					&EventOptions{
						Http: NewHttpFromRequest(r),
					},
				)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func (client Client) log(format string, args ...interface{}) {
	if client.config.Logger != nil {
		client.config.Logger.Printf(format, args...)
	}
}

func uuid4() (string, error) {
	uuid := make([]byte, 16)
	n, err := rand.Read(uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	uuid[8] = 0x80
	uuid[4] = 0x40

	return hex.EncodeToString(uuid), nil
}

func timeoutDialer(cTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

// A custom http.Transport which allows us to put a timeout on each request.
type transport struct {
	httpTransport *http.Transport
	timeout       time.Duration
}

// Make use of Go 1.1's CancelRequest to close an outgoing connection if it
// took longer than [timeout] to get a response.
func (T *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	timer := time.AfterFunc(T.timeout, func() {
		T.httpTransport.CancelRequest(req)
	})
	defer timer.Stop()
	return T.httpTransport.RoundTrip(req)
}
