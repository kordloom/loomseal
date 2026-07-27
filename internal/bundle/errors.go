package bundle

import "errors"

// ErrParse marks input that does not decode as one bundle document.
var ErrParse = errors.New("bundle parse")

// ErrSchema marks a decoded document that breaks the format's structural rules.
var ErrSchema = errors.New("bundle schema")
