package main

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// module is the import prefix every internal edge starts with.
const module = "github.com/kordloom/loomseal"

// allowedImports is the entire dependency graph, pinned. Every production import of one
// package by another must appear here, and every entry here must be used, so the graph can
// neither grow an edge silently nor rot into a list nobody trusts.
//
// The layering this encodes: jcs, merkle, and rfc3161 stand alone at the bottom; bundle
// speaks jcs; chain speaks bundle and merkle; verify speaks all of them and nothing above;
// seal is the one facade exporting internals to producers; cmd is the top and nothing
// imports it. A change that needs a new edge changes this table in the same commit, on
// purpose, with the reasoning in review, which is exactly the decision an agent reaching
// across a boundary skips.
var allowedImports = map[string][]string{
	".":                   {"internal/cmd"},
	"internal/bundle":     {"jcs"},
	"internal/bundletest": {"jcs", "seal"},
	"internal/chain":      {"internal/bundle", "jcs", "merkle"},
	"internal/cmd":        {"internal/jsonutil", "internal/verify", "seal"},
	"internal/jsonutil":   {},
	"internal/verify":     {"internal/bundle", "internal/chain", "jcs", "rfc3161"},
	"jcs":                 {},
	"merkle":              {},
	"rfc3161":             {},
	"seal":                {"internal/bundle", "internal/chain", "jcs"},
	"wasm":                {"internal/verify"},
}

// TestDependencyBoundaries walks every production source file and holds each internal
// import to the pinned graph. Test files are exempt, because a test reaching for a helper
// package is not an architecture, but production code that reaches across a boundary fails
// here on the first import rather than surfacing as a tangle fifty imports later.
func TestDependencyBoundaries(t *testing.T) {
	t.Parallel()
	allowed := make(map[string]map[string]bool, len(allowedImports))
	for pkg, deps := range allowedImports {
		set := make(map[string]bool, len(deps))
		for _, d := range deps {
			set[d] = true
		}
		allowed[pkg] = set
	}
	used := map[string]map[string]bool{}

	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Vectors and examples hold generators run by hand, not linked packages.
			if d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "examples" ||
				d.Name() == "node_modules" || strings.HasPrefix(path, "site") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		pkg := filepath.ToSlash(filepath.Dir(path))
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		set, known := allowed[pkg]
		for _, imp := range f.Imports {
			target := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(target, module) {
				continue
			}
			target = strings.TrimPrefix(strings.TrimPrefix(target, module), "/")
			if !known {
				t.Errorf("%s: package %q is not in the pinned graph; add it with its imports, deliberately",
					path, pkg)
				continue
			}
			if !set[target] {
				t.Errorf("%s: imports %q, which the pinned graph does not allow for %q; "+
					"crossing this boundary is a design decision, so make it in allowedImports "+
					"in the same commit", path, target, pkg)
			}
			if used[pkg] == nil {
				used[pkg] = map[string]bool{}
			}
			used[pkg][target] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A stale allowance is a boundary nobody is holding: it reads as permission the code
	// stopped needing, and the next reach through it looks pre-approved.
	for pkg, deps := range allowedImports {
		for _, d := range deps {
			if !used[pkg][d] {
				t.Errorf("allowedImports permits %q -> %q but no production file uses it; "+
					"remove the stale edge", pkg, d)
			}
		}
	}
}
