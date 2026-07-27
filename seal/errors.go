package seal

import "errors"

// ErrBundle marks input that is not a bundle-shaped JSON object.
var ErrBundle = errors.New("seal bundle")
