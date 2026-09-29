package bundle

// Inclusion is a claim's audit path: the sibling hashes, lowest first, that fold with the claim's
// leaf hash to reproduce the tree root the head names. An empty path is correct and is the only
// value for a log of exactly one leaf.
type Inclusion struct {
	// Path is the audit path, each entry 64 lowercase hex characters.
	Path []string `json:"path"`
}
