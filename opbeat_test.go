package opbeat

import (
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
)

const (
	OpbeatOrganizationID = "2fb217d7dc174736ba54eaa6bb001fb8"
	OpbeatAppID          = "47a72ab277"
	OpbeatSecretToken    = "4eb1179d66d0f52092fd11dc5c2f9156047ff6af"
)

func TestSetup(t *testing.T) {
	Credentials(OpbeatOrganizationID, OpbeatAppID, OpbeatSecretToken)
}

func TestCaptureError(t *testing.T) {
	defer Wait()

	err := CaptureError(errors.New("Test Error"), nil)
	if err != nil {
		t.Error(err)
	}
}

func TestCaptureErrorWithOptions(t *testing.T) {
	defer Wait()

	options := &Options{
		Extra: &Extra{
			"Custom": "Information",
		},
	}

	err := CaptureError(errors.New("Test Error with Options"), options)
	if err != nil {
		t.Error(err)
	}
}

func TestCaptureErrorWithUser(t *testing.T) {
	options := &Options{
		User: &User{
			"Id",
			"Email",
			"Username",
			true,
		},
	}

	err := CaptureError(errors.New("Test Error with User"), options)
	if err != nil {
		t.Error(err)
	}
}

func TestHandler(t *testing.T) {
	defer Wait()

	var interfacy interface{} = "interfacy"
	middleware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(interfacy.([]byte))
	})

	ts := httptest.NewServer(Handler(middleware))
	defer ts.Close()

	_, err := http.Get(ts.URL)
	if err != nil {
		t.Error(err)
	}
}

func TestCaptureMessage(t *testing.T) {
	defer Wait()

	err := CaptureMessage("Test Message", Info, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestRevision(t *testing.T) {
	defer Wait()

	rev, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Error(err)
	}

	DefaultClient.Revision = string(rev[:])

	err = CaptureError(errors.New("Capturing Revision"), nil)
	if err != nil {
		t.Error(err)
	}
}

func TestNewWithLogger(t *testing.T) {
	logger := log.New(os.Stderr, "", log.LstdFlags)

	opbeat := NewWithLogger("organizationID", "appID", "secretToken", logger)

	if opbeat.Logger != logger {
		t.Error("Logger should be set by when calling NewWithLogger")
	}
}

func TestLoggerIsSetByDefault(t *testing.T) {
	opbeat := New("organizationID", "appID", "secretToken")

	if opbeat.Logger == nil {
		t.Error("Logger should be set by default")
	}
}

func TestCaptureMessageWithNilLogger(t *testing.T) {
	defer Wait()

	opbeat := NewWithLogger("organizationID", "appID", "secretToken", nil)

	err := opbeat.CaptureMessage("Test Message", Info, nil)
	if err != nil {
		t.Error(err)
	}
}

func TestClose(t *testing.T) {
	Close()
}
