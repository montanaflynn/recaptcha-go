package recaptcha

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const reCAPTCHALink = "https://www.google.com/recaptcha/api/siteverify"

// VERSION the recaptcha api version
type VERSION int8

const (
	// V2 recaptcha api v2
	V2 VERSION = iota
	// V3 recaptcha api v3, more details can be found here: https://developers.google.com/recaptcha/docs/v3
	V3
	// DefaultThreshold Default minimin score when using V3 api
	DefaultThreshold float32 = 0.5
)

type reCHAPTCHARequest struct {
	Secret   string `json:"secret"`
	Response string `json:"response"`
	RemoteIP string `json:"remoteip,omitempty"`
}

type reCHAPTCHAResponse struct {
	Success        bool      `json:"success"`
	ChallengeTS    time.Time `json:"challenge_ts"`
	Hostname       string    `json:"hostname,omitempty"`
	ApkPackageName string    `json:"apk_package_name,omitempty"`
	Action         string    `json:"action,omitempty"`
	Score          float32   `json:"score,omitempty"`
	ErrorCodes     []string  `json:"error-codes,omitempty"`
}

// custom client so we can mock in tests
type netClient interface {
	PostForm(url string, formValues url.Values) (resp *http.Response, err error)
}

// custom clock so we can mock in tests
type clock interface {
	Since(t time.Time) time.Duration
}

type realClock struct {
}

func (realClock) Since(t time.Time) time.Duration {
	return time.Since(t)
}

// ReCAPTCHA recpatcha holder struct, make adding mocking code simpler.
type ReCAPTCHA struct {
	client        netClient
	Secret        string
	ReCAPTCHALink string
	Version       VERSION
	Timeout       time.Duration
	horloge       clock
}

// Error custom error to pass ErrorCodes and RequestError to user.
type Error struct {
	msg string
	// ErrorCodes contains any error codes from the recaptcha response.
	ErrorCodes []string
	// RequestError is true if the verify request to recaptcha failed.
	RequestError bool
	// ResponseBody holds the raw response body from recaptcha.
	ResponseBody string
}

func (e *Error) Error() string { return e.msg }

// NewReCAPTCHA new ReCAPTCHA instance if version is set to V2 uses recatpcha v2 API
// get your secret from https://www.google.com/recaptcha/admin if version is set to V2
// uses recatpcha v2 API, get your secret from https://g.co/recaptcha/v3
func NewReCAPTCHA(ReCAPTCHASecret string, version VERSION, timeout time.Duration) (ReCAPTCHA, error) {
	if ReCAPTCHASecret == "" {
		return ReCAPTCHA{}, fmt.Errorf("recaptcha secret cannot be blank")
	}
	return ReCAPTCHA{
		client: &http.Client{
			Timeout: timeout,
		},
		horloge:       &realClock{},
		Secret:        ReCAPTCHASecret,
		ReCAPTCHALink: reCAPTCHALink,
		Timeout:       timeout,
		Version:       version,
	}, nil
}

// Verify returns `nil` if no error and the client solved the challenge correctly
func (r *ReCAPTCHA) Verify(challengeResponse string) error {
	body := reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse}
	return r.confirm(body, VerifyOption{})
}

// VerifyOption verification options expected for the challenge
type VerifyOption struct {
	Threshold      float32 // ignored in v2 recaptcha
	Action         string  // ignored in v2 recaptcha
	Hostname       string
	ApkPackageName string
	ResponseTime   time.Duration
	RemoteIP       string
}

// VerifyWithOptions returns `nil` if no error and the client solved the challenge correctly and all options are matching
// `Threshold` and `Action` are ignored when using V2 version
func (r *ReCAPTCHA) VerifyWithOptions(challengeResponse string, options VerifyOption) error {
	var body reCHAPTCHARequest
	if options.RemoteIP == "" {
		body = reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse}
	} else {
		body = reCHAPTCHARequest{Secret: r.Secret, Response: challengeResponse, RemoteIP: options.RemoteIP}
	}
	return r.confirm(body, options)
}

func (r *ReCAPTCHA) confirm(recaptcha reCHAPTCHARequest, options VerifyOption) error {
	var formValues url.Values
	if recaptcha.RemoteIP != "" {
		formValues = url.Values{"secret": {recaptcha.Secret}, "remoteip": {recaptcha.RemoteIP}, "response": {recaptcha.Response}}
	} else {
		formValues = url.Values{"secret": {recaptcha.Secret}, "response": {recaptcha.Response}}
	}

	response, err := r.client.PostForm(r.ReCAPTCHALink, formValues)
	if err != nil {
		return &Error{
			msg:          fmt.Sprintf("error posting to recaptcha endpoint: '%s'", err),
			RequestError: true,
		}
	}
	defer response.Body.Close()

	resultBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return &Error{
			msg:          fmt.Sprintf("couldn't read response body: '%s'", err),
			RequestError: true,
		}
	}

	var result reCHAPTCHAResponse
	err = json.Unmarshal(resultBody, &result)
	if err != nil {
		return &Error{
			msg:          fmt.Sprintf("invalid response body json: '%s'", err),
			RequestError: true,
			ResponseBody: string(resultBody),
		}
	}

	if r.Version == V3 {
		if options.Action != "" && options.Action != result.Action {
			return &Error{
				msg:          fmt.Sprintf("invalid response action '%s', while expecting '%s'", result.Action, options.Action),
				ResponseBody: string(resultBody),
			}
		}
		if options.Threshold != 0 && options.Threshold > result.Score {
			return &Error{
				msg:          fmt.Sprintf("received score '%f', while expecting minimum '%f'", result.Score, options.Threshold),
				ResponseBody: string(resultBody),
			}
		}
		if options.Threshold == 0 && DefaultThreshold > result.Score {
			return &Error{
				msg:          fmt.Sprintf("received score '%f', while expecting minimum '%f'", result.Score, DefaultThreshold),
				ResponseBody: string(resultBody),
			}
		}
	}

	if result.ErrorCodes != nil {
		return &Error{
			msg: fmt.Sprintf("remote error codes: %v", result.ErrorCodes), ErrorCodes: result.ErrorCodes,
			ResponseBody: string(resultBody),
		}
	}

	if !result.Success && recaptcha.RemoteIP != "" {
		return &Error{
			msg:          fmt.Sprintf("invalid challenge solution or remote IP"),
			ResponseBody: string(resultBody),
		}
	} else if !result.Success {
		return &Error{
			msg:          fmt.Sprintf("invalid challenge solution"),
			ResponseBody: string(resultBody),
		}
	}

	if options.Hostname != "" && options.Hostname != result.Hostname {
		return &Error{
			msg:          fmt.Sprintf("invalid response hostname '%s', while expecting '%s'", result.Hostname, options.Hostname),
			ResponseBody: string(resultBody),
		}
	}

	if options.ApkPackageName != "" && options.ApkPackageName != result.ApkPackageName {
		return &Error{
			msg:          fmt.Sprintf("invalid response ApkPackageName '%s', while expecting '%s'", result.ApkPackageName, options.ApkPackageName),
			ResponseBody: string(resultBody),
		}
	}

	if options.ResponseTime != 0 {
		duration := r.horloge.Since(result.ChallengeTS)
		if options.ResponseTime < duration {
			msg := fmt.Sprintf("time spent in resolving challenge '%fs', while expecting maximum '%fs'", duration.Seconds(), options.ResponseTime.Seconds())
			return &Error{
				msg:          msg,
				ResponseBody: string(resultBody),
			}
		}
	}

	return nil
}
