// Experimental Opbeat client. Enables you to log errors and stacktraces from
// within your Go applications, including plug-and-play support for
// `http.Handler` middleware chains.
//
// Usage
//
// A default client is automatically created from environment when the package
// is imported, but you can easily create your own client using the `New`
// function.
//
// 	client := New(organizationId, appId, secretToken)
// 	err := client.CaptureError(errors.New("Test Error"))
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

// Log levels supported by Opbeat.
type Level string

const (
	Debug   Level = "debug"
	Info          = "info"
	Warning       = "warning"
	Error         = "error"
	Fatal         = "fatal"
)

type Opbeat struct {
	packets                            chan *packet
	wait                               sync.WaitGroup
	organizationId, appId, secretToken string
	Host                               string
	Revision                           string
	LoggerName                         string
	*log.Logger
	*http.Client
}

// Creates a new client.
func New(organizationId, appId, secretToken string) *Opbeat {
	opbeat := new(Opbeat)
	opbeat.Credentials(organizationId, appId, secretToken)

	opbeat.Host = defaultHost
	opbeat.Client = &http.Client{
		Timeout: defaultTimeout,
	}

	opbeat.LoggerName = "default"
	opbeat.Logger = log.New(os.Stderr, "", log.LstdFlags)

	opbeat.Start()

	return opbeat
}

// Creates a new client using environment settings.
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

// Configure Opbeat application credentials. These can be found when viewing
// your application settings on the Opbeat website.
func (opbeat *Opbeat) Credentials(organizationId, appId, secretToken string) {
	opbeat.organizationId = organizationId
	opbeat.appId = appId
	opbeat.secretToken = secretToken
}

// HTTP middleware handler that automatically will log any paniced error to
// Opbeat.
func (opbeat *Opbeat) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				if err, ok := err.(error); ok {
					opbeat.CaptureErrorWithRequest(err, r)
				}
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// Captures an error and sends the log to Opbeat.
func (opbeat *Opbeat) CaptureError(err error) error {
	return opbeat.CaptureErrorSkip(err, 1, nil)
}

// Captures an error along with a `*http.Request` and sends the log to Opbeat
// enriched with information specific to that request. Useful when using Opbeat
// in a http application.
func (opbeat *Opbeat) CaptureErrorWithRequest(e error, r *http.Request) error {
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

	http := map[string]interface{}{
		"url":     scheme + "://" + r.Host + r.URL.String(),
		"method":  r.Method,
		"headers": headers,
	}

	return opbeat.CaptureErrorSkip(e, 4, map[string]interface{}{
		"http": http,
	})
}

// Captures an error and skips `skip` amount of frames in the stacktrace, this
// is useful to stop logging library type frames to Opbeat. Also takes a map of
// other interfaces that are written to Opbeat as a part of the log. Please take
// care that any values in this map can be marshalled into JSON.
func (opbeat *Opbeat) CaptureErrorSkip(e error, skip int, options map[string]interface{}) error {
	stacktrace, err := stacko.NewStacktrace(3 + skip)
	if err != nil {
		return err
	}

	p, err := newPacket(e.Error(), stacktrace)
	if err != nil {
		return err
	}

	p.Revision = opbeat.Revision
	p.Level = Error
	p.Logger = opbeat.LoggerName

	if http, ok := options["http"].(map[string]interface{}); ok {
		p.HTTP = http
	}

	opbeat.queue(p)

	return nil
}

// Captures a message along with a level indicating the severity of the message.
func (opbeat *Opbeat) CaptureMessage(message string, l Level) error {
	p, err := newPacket(message, nil)
	if err != nil {
		return err
	}

	p.Level = l

	opbeat.queue(p)

	return nil
}

// Waits for all packets to send.
func (opbeat *Opbeat) Wait() {
	opbeat.wait.Wait()
}

// Starts a goroutine which listens on the main channel and sends any packets it
// receives to Opbeat. The goroutine will exit if the client's `.Close` function
// is called.
func (opbeat *Opbeat) Start() {
	opbeat.packets = make(chan *packet)
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

// Waits for all requests to finish and closes the main channel. Closing the
// channel will force the goroutines communicating packets to return.
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
		opbeat.Host, opbeat.organizationId, opbeat.appId)

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

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	res.Body.Close()

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
// function and by setting fields directly on the `DefaultOpbeat` variable.
// You may find function specific documentation on the corresponding functions
// on the `*Opbeat` struct.
var DefaultOpbeat = NewFromEnvironment()

func Credentials(organizationId, appId, secretToken string) {
	DefaultOpbeat.Credentials(organizationId, appId, secretToken)
}

func Handler(h http.Handler) http.Handler {
	return DefaultOpbeat.Handler(h)
}

func CaptureError(err error) error {
	return DefaultOpbeat.CaptureError(err)
}

func CaptureMessage(message string, l Level) error {
	return DefaultOpbeat.CaptureMessage(message, l)
}

func Wait() {
	DefaultOpbeat.Wait()
}

func Start() {
	DefaultOpbeat.Start()
}

func Close() {
	DefaultOpbeat.Close()
}

type packet struct {
	Id         string                 `json:"client_supplied_id"`
	Culprit    string                 `json:"culprit"`
	Timestamp  string                 `json:"timestamp"`
	Revision   string                 `json:"rev"`
	Message    string                 `json:"message"`
	Level      Level                  `json:"level"`
	Logger     string                 `json:"logger"`
	Exception  map[string]string      `json:"exception"`
	Machine    map[string]string      `json:"machine"`
	Extra      map[string]interface{} `json:"extra"`
	Stacktrace map[string][]frame     `json:"stacktrace"`
	HTTP       map[string]interface{} `json:"http"`
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

func newPacket(message string, stacktrace stacko.Stacktrace) (*packet, error) {
	id := make([]byte, 24)
	rand.Read(id)

	p := new(packet)
	p.Message = message
	p.Id = base64.URLEncoding.EncodeToString(id)

	p.Timestamp = time.Now().UTC().Format(time.RFC3339)
	p.Machine = map[string]string{
		"hostname": "Unknown",
	}

	hostname, err := os.Hostname()
	if err == nil {
		p.Machine["hostname"] = hostname
	}

	p.Extra = map[string]interface{}{
		"Version":      runtime.Version(),
		"Compiler":     runtime.Compiler,
		"Architecture": runtime.GOARCH,
		"OS":           runtime.GOOS,
		"Processors":   runtime.NumCPU(),
		"Goroutines":   runtime.NumGoroutine(),
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
