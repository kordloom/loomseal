package verify

import "errors"

// ErrFingerprint is returned for a producer key pin in any form but sha256: and 64 lowercase hex
// digits, the only form a key fingerprint takes. Such a pin names no key, so a caller who meant to
// pin would otherwise either fail against every bundle or, for an empty pin, pass unpinned.
var ErrFingerprint = errors.New("fingerprint is not sha256: and 64 lowercase hex digits")

// ErrUnsupportedPresentation marks a presentation declaring a version this verifier does not
// implement. As for a bundle, it is fail-closed and distinct from a verification failure, because
// "this verifier is too old for this presentation" and "this presentation did not verify" must
// never share a message.
var ErrUnsupportedPresentation = errors.New("unsupported presentation")

// ErrExpectation is returned for an expected presentation audience or nonce the caller supplied
// empty. An empty expectation compares against nothing, so read as no expectation it would skip the
// replay defense under the outcome of a checked run.
var ErrExpectation = errors.New("expected value is empty and compares against nothing")
