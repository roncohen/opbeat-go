/*
Package opbeat-go is an experimental client for sending messages and exceptions to Opbeat: https://opbeat.com

Usage

Create a new client using the NewClient() function. After the client has been created use the CaptureMessage or CaptureError
methods to send messages and errors to the Opbeat. Variables loaded are: OPBEAT_ORGANIZATION_ID, OPBEAT_APP_ID, OPBEAT_SECRET_TOKEN, OPBEAT_HOST, OPBEAT_CONNECT_TIMEOUT, OPBEAT_READ_TIMEOUT

	client, err := opbeat.NewClientFromEnv()
	...
	id, err := client.CaptureMessage("some text")

If you want to have more finegrained control over the send event, you can create the event instance yourself

	client.Capture(&opbeat.Event{Message: "Some Text", Logger:"auth"})

Example

A complete example could look like this:

	config := ClientConfig{
		OrganizationId: OrgId,
		AppId:          AppId,
		SecretToken:    SecretToken,
		Logger:         log.New(os.Stderr, "OPBEAT ", log.LstdFlags),
	}

	client, _ := NewClient(&config)
	_, err := client.CaptureErrorWithOptions(
		errors.New("Waaat!"),
		&EventOptions{
			User: &User{
				Id:              "99",
				Username:        "roncohen",
				Email:           "ron@opbeat.com",
				IsAuthenticated: true,
			},
			Http: NewHttpFromRequest(req),
			Extra: &map[string]interface{}{"hello": "world"},
		},
	)

Http Handler

This library comes with a convenient http handler that plugs right into your handler chain:

	client, _ := NewClient(&config)
	var somethingInterfacy interface{} = "a string"

	s := http.NewServer(
		OpbeatHandler(client, http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// A mistake
				w.Write(somethingInterfacy.([]byte))
			})
		)
	)

*/
package opbeat
