// Package opbeat is an experimental Opbeat client. Enables you to log errors
// and stacktraces from within your Go applications, including plug-and-play
// support for `http.Handler` middleware chains.
//
// Usage
//
// A default client is automatically created from environment when the package
// is imported, but you can easily create your own client using the `New`
// function.
//
// 	client := New(organizationId, appId, secretToken)
// 	err := client.CaptureError(errors.New("Test Error"), nil)
// 	...
//
// Every client can call the `.CaptureX` functions for example `.CaptureError`
// and `.CaptureMessage` and these are the main functions that are used to
// communicate information to Opbeat.
//
// Importantly there is also a `.Handler` function on every client that allows
// for painless error handling in any Go http application that uses the standard
// form `http.Handler` functions.
//
// 	var interfacy interface{} = "interfacy"
// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Write(interfacy.([]byte))
// 	})
// 	s := http.NewServer(opbeat.Handler(handler))
//
// The example above would automatically tell Opbeat that we tried to type
// assert a string into a []byte and failed. You may have figured out that this
// works by recovering from panics, that means that you may also panic any error
// in your http application and it will be logged by the client.
//
// Environment
//
// The client supports the following environment variables.
//
// - OPBEAT_ORGANIZATION_ID
// - OPBEAT_APP_ID
// - OPBEAT_SECRET_TOKEN
// - OPBEAT_HOST
// - OPBEAT_REVISION
// - OPBEAT_TIMEOUT
//
// They will all be automatically loaded into the default client.
package opbeat

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hallas/stacko"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

const (
	defaultHost    = "opbeat.com"
	defaultTimeout = 3 * time.Second
)

// Level is a type of string that represents an opbeat message level.
type Level string

// Use any of these constants as an indication of the severity level of an
// opbeat message.
const (
	Debug   Level = "debug"
	Info          = "info"
	Warning       = "warning"
	Error         = "error"
	Fatal         = "fatal"
)

// Options is a struct used to customise an opbeat message. Use it by setting
// its pointers to structs with additional custom information.
type Options struct {
	*Extra
	*User
	*HTTP
}

// Extra is a map of custom string keys and interface{} values. This map will be
// JSON serialized and sent to opbeat where you can view them along with the
// other information pertaining to that message.
type Extra map[string]interface{}

// User is a struct of typical user information such as an id and an email. Use
// this when logging an error in an environment where you have information on
// the user active in the context of the error.
type User struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	Username        string `json:"username"`
	IsAuthenticated bool   `json:"is_authenticated"`
}

// HTTP is a struct describing an HTTP request. Use this when in the context of
// an HTTP request.
type HTTP struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
}

// Opbeat is a struct used to communicate with Opbeat. Instantiate this directly
// to create your own client, however we recommend using the `New` functions.
type Opbeat struct {
	packets                            chan *packet
	wait                               sync.WaitGroup
	organizationID, appID, secretToken string
	Host                               string
	Revision                           string
	LoggerName                         string
	*log.Logger
	*http.Client
}

// New creates a new Opbeat client with default settings.
func New(organizationID, appID, secretToken string) *Opbeat {
	opbeat := new(Opbeat)
	opbeat.Credentials(organizationID, appID, secretToken)

	opbeat.Host = defaultHost
	opbeat.Client = &http.Client{
		Timeout: defaultTimeout,
	}

	opbeat.LoggerName = "default"
	opbeat.Logger = log.New(os.Stderr, "", log.LstdFlags)

	opbeat.start()

	return opbeat
}

// NewFromEnvironment creates a new client using environment settings.
func NewFromEnvironment() *Opbeat {
	opbeat := New(os.Getenv("OPBEAT_ORGANIZATION_ID"), os.Getenv("OPBEAT_APP_ID"),
		os.Getenv("OPBEAT_SECRET_TOKEN"))

	host := os.Getenv("OPBEAT_HOST")
	if len(host) > 0 {
		opbeat.Host = host
	}

	rev := os.Getenv("OPBEAT_REVISION")
	if len(rev) > 0 {
		opbeat.Revision = rev
	}

	timeout := os.Getenv("OPBEAT_TIMEOUT")
	if len(timeout) > 0 {
		timeoutSec, err := strconv.Atoi(timeout)
		if err != nil {
			opbeat.Logger.Print(err)
		} else {
			opbeat.Client.Timeout = time.Duration(timeoutSec) * time.Second
		}
	}

	return opbeat
}

// Credentials configures your Opbeat application credentials. These can be
// found when viewing your application settings on the Opbeat website.
func (opbeat *Opbeat) Credentials(organizationID, appID, secretToken string) {
	opbeat.organizationID = organizationID
	opbeat.appID = appID
	opbeat.secretToken = secretToken
}

// Handler is an HTTP middleware handler that automatically will log any paniced
// error to Opbeat.
func (opbeat *Opbeat) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if err, ok := err.(error); ok {
					opbeat.CaptureErrorWithRequest(err, r, nil)
				}
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// CaptureError captures an error and sends the log to Opbeat.
func (opbeat *Opbeat) CaptureError(err error, options *Options) error {
	return opbeat.CaptureErrorSkip(err, 1, options)
}

// CaptureErrorWithRequest captures an error along with a `*http.Request` and
// sends the log to Opbeat enriched with information specific to that request.
// Useful when using Opbeat in a http application.
func (opbeat *Opbeat) CaptureErrorWithRequest(e error, r *http.Request, options *Options) error {
	headers := make(map[string]string)
	for k, v := range r.Header {
		headers[k] = v[len(v)-1]
	}

	scheme := ""
	if r.TLS != nil {
		scheme = "https"
	} else {
		scheme = "http"
	}

	http := HTTP{
		scheme + "://" + r.Host + r.URL.String(),
		r.Method,
		headers,
	}

	if options == nil {
		options = new(Options)
	}

	options.HTTP = &http

	return opbeat.CaptureErrorSkip(e, 4, options)
}

// CaptureErrorSkip captures an error and skips `skip` amount of frames in the
// stacktrace, this is useful to stop logging library type frames to Opbeat.
// Also takes a map of other interfaces that are written to Opbeat as a part of
// the log. Please take care that any values in this map can be marshalled into
// JSON.
func (opbeat *Opbeat) CaptureErrorSkip(e error, skip int, options *Options) error {
	stacktrace, err := stacko.NewStacktrace(3 + skip)
	if err != nil {
		return err
	}

	p, err := newPacket(e.Error(), stacktrace, options)
	if err != nil {
		return err
	}

	p.Revision = opbeat.Revision
	p.Level = Error
	p.Logger = opbeat.LoggerName

	opbeat.queue(p)

	return nil
}

// CaptureMessage captures a message along with a level indicating the severity
// of the message.
func (opbeat *Opbeat) CaptureMessage(message string, l Level, options *Options) error {
	p, err := newPacket(message, nil, options)
	if err != nil {
		return err
	}

	p.Level = l

	opbeat.queue(p)

	return nil
}

// Wait waits for all packets to send.
func (opbeat *Opbeat) Wait() {
	opbeat.wait.Wait()
}

// Starts a goroutine which listens on the main channel and sends any packets it
// receives to Opbeat. The goroutine will exit if the client's `.Close` function
// is called.
func (opbeat *Opbeat) start() {
	opbeat.packets = make(chan *packet, 20)
	go func() {
		var p *packet
		var open bool
		for {
			select {
			case p, open = <-opbeat.packets:
				if !open {
					return
				}
				err := opbeat.send(p)
				if err != nil {
					opbeat.Logger.Println(err)
				}
				opbeat.wait.Done()
			}
		}
	}()
}

// Close waits for all requests to finish and closes the main channel. Closing
// the channel will force the goroutines communicating packets to return. This
// effectively kills the client and a new will have to be created to continue
// communicating with Opbeat.
func (opbeat *Opbeat) Close() {
	opbeat.Wait()
	close(opbeat.packets)
}

func (opbeat *Opbeat) queue(p *packet) {
	opbeat.wait.Add(1)
	opbeat.packets <- p
}

func (opbeat *Opbeat) send(p *packet) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s/api/v1/organizations/%s/apps/%s/errors/",
		opbeat.Host, opbeat.organizationID, opbeat.appID)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+opbeat.secretToken)

	res, err := opbeat.Client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	switch res.StatusCode {
	case 202:
		if res.Header["Location"] != nil {
			opbeat.Logger.Printf("Event details at %s", res.Header["Location"][0])
		}
		return nil
	default:
		if err != nil {
			return err
		}

		err = fmt.Errorf("Opbeat response %v: %s", res.Status, string(body[:]))
		return err
	}

	return nil
}

// The default client, created fresh from the environment on import. Can also be
// used without the environment by manually configuring via the `.Credentials`
// function and by setting fields directly on the `DefaultClient` variable.
// You may find function specific documentation on the corresponding functions
// on the `*Opbeat` struct.
var DefaultClient = NewFromEnvironment()

// Credentials wraps the default client.
func Credentials(organizationID, appID, secretToken string) {
	DefaultClient.Credentials(organizationID, appID, secretToken)
}

// Handler wraps the default client.
func Handler(h http.Handler) http.Handler {
	return DefaultClient.Handler(h)
}

// CaptureError wraps the default client.
func CaptureError(err error, options *Options) error {
	return DefaultClient.CaptureError(err, options)
}

// CaptureErrorWithRequest wraps the default client.
func CaptureErrorWithRequest(e error, r *http.Request, options *Options) error {
	return DefaultClient.CaptureErrorWithRequest(e, r, options)
}

// CaptureMessage wraps the default client.
func CaptureMessage(message string, l Level, options *Options) error {
	return DefaultClient.CaptureMessage(message, l, options)
}

// Wait wraps the default client.
func Wait() {
	DefaultClient.Wait()
}

// Close wraps the default client.
func Close() {
	DefaultClient.Close()
}

type packet struct {
	ID         string             `json:"client_supplied_id"`
	Culprit    string             `json:"culprit"`
	Timestamp  string             `json:"timestamp"`
	Revision   string             `json:"rev"`
	Message    string             `json:"message"`
	Level      Level              `json:"level"`
	Logger     string             `json:"logger"`
	Exception  map[string]string  `json:"exception"`
	Machine    map[string]string  `json:"machine"`
	Stacktrace map[string][]frame `json:"stacktrace"`
	Extra      *Extra             `json:"extra"`
	HTTP       *HTTP              `json:"http"`
	User       *User              `json:"user"`
}

type frame struct {
	FileName     string   `json:"filename"`
	FunctionName string   `json:"function"`
	PackageName  string   `json:"-"`
	Path         string   `json:"abs_path"`
	LineNumber   int      `json:"lineno"`
	InApp        bool     `json:"in_app"`
	PreContext   []string `json:"pre_context"`
	PostContext  []string `json:"post_context"`
	Context      string   `json:"context_line"`
}

func newPacket(message string, stacktrace stacko.Stacktrace, options *Options) (*packet, error) {
	id := make([]byte, 24)
	rand.Read(id)

	p := new(packet)
	p.Message = message
	p.ID = base64.URLEncoding.EncodeToString(id)

	p.Timestamp = time.Now().UTC().Format(time.RFC3339)
	p.Machine = map[string]string{
		"hostname": "Unknown",
	}

	hostname, err := os.Hostname()
	if err == nil {
		p.Machine["hostname"] = hostname
	}

	extra := Extra{
		"Version":      runtime.Version(),
		"Compiler":     runtime.Compiler,
		"Architecture": runtime.GOARCH,
		"OS":           runtime.GOOS,
		"Processors":   runtime.NumCPU(),
		"Goroutines":   runtime.NumGoroutine(),
	}

	if options != nil {
		p.HTTP = options.HTTP
		p.User = options.User

		if options.Extra != nil {
			for k, v := range *options.Extra {
				extra[k] = v
			}
		}

		p.Extra = &extra
	}

	if stacktrace != nil {
		p.Stacktrace = map[string][]frame{"frames": prepareStacktrace(stacktrace)}

		origin := stacktrace[0]
		p.Culprit = origin.FunctionName
		p.Exception = map[string]string{
			"type":   "Error",
			"value":  message,
			"module": origin.PackageName,
		}
	}

	return p, nil
}

func prepareStacktrace(stacktrace stacko.Stacktrace) []frame {
	frames := make([]frame, len(stacktrace))
	for i, f := range stacktrace {
		frames[i] = frame{
			f.FileName,
			f.FunctionName,
			f.PackageName,
			f.Path,
			f.LineNumber,
			f.InDomain,
			f.PreContext,
			f.PostContext,
			f.Context,
		}
	}
	return frames
}
