package releasepolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func DecodeStrict[T any](reader io.Reader) (T, error) {
	var value T
	content, err := io.ReadAll(io.LimitReader(reader, maxJSONSize+1))
	if err != nil {
		return value, fmt.Errorf("read JSON: %w", err)
	}
	if len(content) > maxJSONSize {
		return value, fmt.Errorf("decode JSON: size limit exceeded")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return value, fmt.Errorf("decode JSON: trailing data")
	}
	return value, nil
}

func Encode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
