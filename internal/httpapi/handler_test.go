package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	expectedHealthBody = "{\"status\":\"ok\"}\n"
	expectedDigestBody = "{\"algorithm\":\"sha256\",\"digest\":\"3f412634a4ea9da04b558d0e32b0062a692e41a1c1d10f0c5c707f14440392ce\"}\n"
)

func TestHealthz(t *testing.T) {
	t.Parallel()

	response := serveRequest(t, New(), http.MethodGet, "/healthz", "", "")

	assertResponse(t, response, http.StatusOK, expectedHealthBody)
}

func TestDigest(t *testing.T) {
	t.Parallel()

	handler := New()
	first := serveRequest(t, handler, http.MethodPost, "/v1/digest", `{"value":"supply-chain"}`, "application/json")
	second := serveRequest(t, handler, http.MethodPost, "/v1/digest", `{"value":"supply-chain"}`, "application/json")

	assertResponse(t, first, http.StatusOK, expectedDigestBody)
	assertResponse(t, second, http.StatusOK, expectedDigestBody)
	if first.Body.String() != second.Body.String() {
		t.Fatalf("repeated requests returned different bodies: %q != %q", first.Body.String(), second.Body.String())
	}
}

func TestDigestRejectsInvalidRequests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		contentType string
		wantStatus  int
		wantCode    string
	}{
		{
			name:        "empty value",
			body:        `{"value":""}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "value above one kibibyte",
			body:        `{"value":"` + strings.Repeat("a", 1025) + `"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "malformed json",
			body:        `{"value":`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "unknown field",
			body:        `{"value":"ok","extra":true}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:        "trailing json",
			body:        `{"value":"ok"}{"value":"again"}`,
			contentType: "application/json",
			wantStatus:  http.StatusBadRequest,
			wantCode:    "invalid_request",
		},
		{
			name:       "absent content type",
			body:       `{"value":"ok"}`,
			wantStatus: http.StatusUnsupportedMediaType,
			wantCode:   "unsupported_media_type",
		},
		{
			name:        "non json content type",
			body:        `{"value":"ok"}`,
			contentType: "text/plain",
			wantStatus:  http.StatusUnsupportedMediaType,
			wantCode:    "unsupported_media_type",
		},
		{
			name:        "body above four kibibytes",
			body:        `{"value":"` + strings.Repeat("a", 4096) + `"}`,
			contentType: "application/json",
			wantStatus:  http.StatusRequestEntityTooLarge,
			wantCode:    "request_too_large",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := serveRequest(t, New(), http.MethodPost, "/v1/digest", test.body, test.contentType)
			wantBody := "{\"error\":{\"code\":\"" + test.wantCode + "\",\"message\":\"" + errorMessage(test.wantCode) + "\"}}\n"
			assertResponse(t, response, test.wantStatus, wantBody)
		})
	}
}

func TestUnsupportedMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "health", method: http.MethodPost, path: "/healthz"},
		{name: "digest", method: http.MethodGet, path: "/v1/digest"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := serveRequest(t, New(), test.method, test.path, "", "")
			assertResponse(
				t,
				response,
				http.StatusMethodNotAllowed,
				"{\"error\":{\"code\":\"method_not_allowed\",\"message\":\"request method is not allowed\"}}\n",
			)
		})
	}
}

func TestResponseSecurityHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		method      string
		path        string
		body        string
		contentType string
	}{
		{name: "successful response", method: http.MethodGet, path: "/healthz"},
		{
			name:        "error response",
			method:      http.MethodPost,
			path:        "/v1/digest",
			body:        `{"value":""}`,
			contentType: "application/json",
		},
	}

	wantHeaders := map[string]string{
		"Content-Type":           "application/json",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
		"Content-Security-Policy": "default-src 'none'; " +
			"frame-ancestors 'none'",
		"Referrer-Policy": "no-referrer",
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			response := serveRequest(t, New(), test.method, test.path, test.body, test.contentType)
			for name, want := range wantHeaders {
				if got := response.Header().Get(name); got != want {
					t.Errorf("header %s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func serveRequest(t *testing.T, handler http.Handler, method, path, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	return response
}

func assertResponse(t *testing.T, response *httptest.ResponseRecorder, wantStatus int, wantBody string) {
	t.Helper()

	if response.Code != wantStatus {
		t.Errorf("status = %d, want %d", response.Code, wantStatus)
	}
	if got := response.Body.String(); got != wantBody {
		t.Errorf("body = %q, want %q", got, wantBody)
	}
}

func errorMessage(code string) string {
	switch code {
	case "unsupported_media_type":
		return "content type must be application/json"
	case "request_too_large":
		return "request body is too large"
	default:
		return "request body is invalid"
	}
}
