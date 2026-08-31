package bundle

import "errors"

// ErrParse marks input that does not decode as one bundle document.
var ErrParse = errors.New("bundle parse")

// ErrSchema marks a decoded document that breaks the format's structural rules.
var ErrSchema = errors.New("bundle schema")

// ErrUnsupported marks a document declaring a version, profile, or algorithm this verifier does
// not implement. It is fail-closed and never becomes a green verdict, but it is distinct from a
// verification failure, because "this verifier is too old for this bundle" and "this bundle did
// not verify" must never share a message.
var ErrUnsupported = errors.New("unsupported bundle")
