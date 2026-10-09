package verify

import (
	"strconv"
	"unicode"
)

// Printable returns s as a report line shows it: unchanged when every character prints, and quoted
// otherwise. A member name, or a detail naming one, is written by whoever produced the bundle, and
// one carrying a control or format character must neither act on the terminal reading it nor
// reorder the line around it. The command line and the browser page both write such text through
// it, so the two show the same line.
func Printable(s string) string {
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return strconv.Quote(s)
		}
	}
	return s
}
