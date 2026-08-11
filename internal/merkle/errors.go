package merkle

import "errors"

// ErrRange is returned when an index or size names a position the log does not hold.
var ErrRange = errors.New("merkle: out of range")
