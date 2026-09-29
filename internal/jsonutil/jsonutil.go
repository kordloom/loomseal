// Package jsonutil centralizes JSON output encoding for the CLI.
package jsonutil

import "encoding/json"

// Marshal encodes v compactly, or indented when pretty is set.
func Marshal(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}
