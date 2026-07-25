package migrations

import "embed"

// Files contains the embedded SQLite migration files.
//
//go:embed *.sql
var Files embed.FS
