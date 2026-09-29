package jcs

import "errors"

// ErrParse marks input that is not one well-formed JSON value with unique object keys.
var ErrParse = errors.New("jcs parse")

// ErrNumber marks a number outside the LoomSeal profile: integers within 2^53 only.
var ErrNumber = errors.New("jcs number")

// ErrType marks a Go value Serialize does not support.
var ErrType = errors.New("jcs type")
