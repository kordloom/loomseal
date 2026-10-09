package bundle

import "fmt"

// MaxDepth is the deepest a bundle or presentation document may nest, counting each array or
// object as one level and the outermost as the first. It is the bound every shipped verifier
// holds, the browser build included, whose WebAssembly stack is the smallest of the three.
const MaxDepth = 3200

// CheckDepth refuses a document nested deeper than limit levels, MaxDepth for a whole bundle or
// presentation. It walks the bytes once without recursion, so a document built to exhaust a stack
// is refused before any recursive reader sees it. A bracket inside a string is text and does not
// count.
func CheckDepth(raw []byte, limit int) error {
	depth, inString, escaped := 0, false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
		case c == '[' || c == '{':
			depth++
			if depth > limit {
				return fmt.Errorf("%w: nesting exceeds %d levels", ErrParse, limit)
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return nil
}
