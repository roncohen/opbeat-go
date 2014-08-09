package opbeat

import (
	"compress/zlib"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
)

func TestNewClientSetsProperties(t *testing.T) {
	config := ClientConfig{
		OrganizationId: "org_id",
		AppId:          "app_id",
		SecretToken:    "token",
	}
	client, err := NewClient(&config)

	if err != nil {
		t.Error(err)
	}

	if client.config.OrganizationId != config.OrganizationId {
		t.Error("OrganizationId was not set")
	}

	if client.config.AppId != config.AppId {
		t.Error("AppId was not set")
	}

	if client.URL.Scheme != "https" {
		t.Error("url scheme must be https")
	}

	if client.config.ReadTimeout != defaultTimeout {
		t.Error("did not set ReadTimeout")
	}

	if client.config.ConnectTimeout != defaultTimeout {
		t.Error("did not set ReadTimeout")
	}
}

func SkipTestClientIntegrationAgainstOpbeatCom(t *testing.T) {
	config := ClientConfig{
		OrganizationId: "733513d2c0bf4d4ba783a33380e87960",
		AppId:          "4093730eb9",
		SecretToken:    "aeb10c7cb87f2ba40a26d1981ee3c3d0e585dcdf",
	}
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	client, _ := NewClient(&config)
	_, err := client.CaptureMessageWithOptions(
		"message",
		&EventOptions{
			Extra: &map[string]interface{}{"hello": "world"},
			User: &User{
				Id:              "99",
				Username:        "roncohen",
				Email:           "ron@opbeat.com",
				IsAuthenticated: true,
			},
			Http: NewHttpFromRequest(req),
		},
	)

	if err != nil {
		t.Error(err)
	}
}

func testRequest(t *testing.T, test_call func(*testing.T, *Client), assertions func(map[string]interface{})) {
	OrgId := "733513d2c0bf4d4ba783a33380e87960"
	AppId := "4093730eb9"
	SecretToken := "aeb10c7cb87f2ba40a26d1981ee3c3d0e585dcdf"

	expected_url := "/api/v1/organizations/" + OrgId
	expected_url = expected_url + "/apps/" + AppId
	expected_url = expected_url + "/errors/"

	var do_you_even_request_bro = false
	ts := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			if r.URL.String() != expected_url {
				t.Errorf("Expected url %v, was %v", expected_url, r.URL)
			}
			do_you_even_request_bro = true
			var requestBody = make(map[string]interface{})
			reader, err := zlib.NewReader(r.Body)
			if err != nil {
				t.Error(err)
			}
			jsonDecoder := json.NewDecoder(reader)
			jsonDecoder.Decode(&requestBody)
			reader.Close()

			assertions(requestBody)
		}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)

	config := ClientConfig{
		OrganizationId: OrgId,
		AppId:          AppId,
		SecretToken:    SecretToken,
		Host:           u.Host,
		SkipVerify:     true,
	}

	client, _ := NewClient(&config)

	test_call(t, client)

	if !do_you_even_request_bro {
		t.Fatal("No request sent")
	}
}

func TestCaptureMessageStackSize(t *testing.T) {
	testRequest(
		t,
		func(t *testing.T, client *Client) {
			client.CaptureMessage("My message")
		},
		func(requestBody map[string]interface{}) {
			if requestBody["message"] != "My message" {
				t.Errorf("Message not set correctly body=%v", requestBody)
			}
			frames := requestBody["stacktrace"].(map[string]interface{})["frames"].([]interface{})

			if len(frames) != 4 {
				t.Errorf("Expected 4 frames stacktrace=%v", frames)
			}
		},
	)
}

func TestCaptureStackSize(t *testing.T) {
	testRequest(
		t,
		func(t *testing.T, client *Client) {
			client.Capture(&Event{Message: "Hello!"})
		},
		func(requestBody map[string]interface{}) {
			if requestBody["message"] != "Hello!" {
				t.Errorf("Message not set correctly body=%v", requestBody)
			}
			frames := requestBody["stacktrace"].(map[string]interface{})["frames"].([]interface{})

			if len(frames) != 4 {
				t.Errorf("Expected 4 frames stacktrace=%v", frames)
			}
		},
	)
}

func TestCaptureErrorStackSize(t *testing.T) {
	testRequest(
		t,
		func(t *testing.T, client *Client) {
			client.CaptureError(errors.New("My error"))
		},
		func(requestBody map[string]interface{}) {
			if requestBody["message"] != "My error" {
				t.Errorf("Message not set correctly body=%v", requestBody)
			}
			frames := requestBody["stacktrace"].(map[string]interface{})["frames"].([]interface{})

			if len(frames) != 4 {
				t.Errorf("Expected 4 frames stacktrace=%v", frames)
			}
		},
	)
}

func TestCaptureErrorWithOptionsStackSize(t *testing.T) {
	testRequest(
		t,
		func(t *testing.T, client *Client) {
			client.CaptureErrorWithOptions(errors.New("My error"), &EventOptions{
				Http: &Http{
					Url:    "http://example.com",
					Method: "PATCH",
					Headers: map[string]string{
						"header1": "value1",
					},
				},
				User: &User{
					Id:       "99",
					Username: "roncohen",
					Email:    "ron@opbeat.com",
				},
			})
		},
		func(requestBody map[string]interface{}) {
			if requestBody["message"] != "My error" {
				t.Errorf("Message not set correctly body=%v", requestBody)
			}
			frames := requestBody["stacktrace"].(map[string]interface{})["frames"].([]interface{})

			if len(frames) != 4 {
				t.Errorf("Expected 4 frames stacktrace=%v", frames)
			}

			http := requestBody["http"].(map[string]interface{})
			if http["url"] != "http://example.com" {
				t.Errorf("expected http/url to be 'http://example.com' was %v", http["url"])
			}

			if http["method"] != "PATCH" {
				t.Errorf("expected http/method to be 'PATCH' was %v", http["method"])
			}

			expected_headers := map[string]string{
				"header1": "value1",
			}

			if reflect.DeepEqual(http["headers"], expected_headers) {
				t.Errorf("expected http/headers to be %v but was %v", expected_headers, http["method"])
			}

			expected_hostname, _ := os.Hostname()

			machine := requestBody["machine"].(map[string]interface{})
			if machine["hostname"] != expected_hostname {
				t.Errorf("expected machine/hostname to be '%v', was '%v'", expected_hostname, machine["hostname"])
			}
		},
	)
}
