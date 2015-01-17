package opbeat

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
)

const (
	OpbeatOrganizationId = "2fb217d7dc174736ba54eaa6bb001fb8"
	OpbeatAppId          = "47a72ab277"
	OpbeatSecretToken    = "4eb1179d66d0f52092fd11dc5c2f9156047ff6af"
)

func TestSetup(t *testing.T) {
	Credentials(OpbeatOrganizationId, OpbeatAppId, OpbeatSecretToken)
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

	DefaultOpbeat.Revision = string(rev[:])

	err = CaptureError(errors.New("Capturing Revision"), nil)
	if err != nil {
		t.Error(err)
	}
}

func TestClose(t *testing.T) {
	Close()
}
