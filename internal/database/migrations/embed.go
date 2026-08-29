// Package migrations carries the versioned SQL compiled into every binary.
//
// The files live beside this file rather than under internal/database/migrate
// because go:embed cannot reach a sibling directory — and keeping the SQL in
// its own package is better anyway: the runner in internal/database/migrate has
// no knowledge of this schema, so it stays a general-purpose component and is
// testable against fixture migrations rather than the real ones.
//
// Embedding matters operationally. A binary that carries its own schema can
// migrate itself on startup, in a container, with no volume mount and no
// separate artefact to keep in step with the image.
package migrations

import "embed"

// FS holds every migration file.
//
//go:embed *.sql
var FS embed.FS

// Dir is the path to pass to migrate.Load for this filesystem. The files sit at
// the root of the embedded FS, so it is ".".
const Dir = "."
