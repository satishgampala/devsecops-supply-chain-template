package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

const (
	maxRequestBodyBytes = 4 << 10
	maxDigestValueBytes = 1 << 10
)

type digestRequest struct {
	Value string `json:"value"`
}

type digestResponse struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// New returns an isolated API handler with no global mux registrations.
func New() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /v1/digest", handleDigest)
	mux.Handle("/healthz", methodNotAllowed(http.MethodGet))
	mux.Handle("/v1/digest", methodNotAllowed(http.MethodPost))

	return withSecurityHeaders(mux)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func handleDigest(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(
			w,
			http.StatusUnsupportedMediaType,
			"unsupported_media_type",
			"content type must be application/json",
		)
		return
	}

	if r.ContentLength > maxRequestBodyBytes {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var request digestRequest
	if err := decoder.Decode(&request); err != nil {
		writeDecodeError(w, err)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeDecodeError(w, err)
		return
	}
	if len(request.Value) == 0 || len(request.Value) > maxDigestValueBytes {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}

	digest := sha256.Sum256([]byte(request.Value))
	writeJSON(w, http.StatusOK, digestResponse{
		Algorithm: "sha256",
		Digest:    hex.EncodeToString(digest[:]),
	})
}

func methodNotAllowed(allowedMethod string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", allowedMethod)
		writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "request method is not allowed")
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeAPIError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		return
	}

	writeAPIError(w, http.StatusBadRequest, "invalid_request", "request body is invalid")
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: apiError{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
