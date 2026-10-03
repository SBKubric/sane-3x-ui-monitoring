// Package store is mon-server's whole persistence layer: one SQLite file
// (spec §3) holding the registry, the state machine, the outbox to the panel
// and the admin's own login. Every other package reaches the database only
// through *Store — no package outside store opens gorm.DB directly, so this
// file is the one place that knows the DSN, the pragmas and the migration
// order.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// Store wraps the single GORM connection mon-server keeps open for its
// SQLite file. DB is exported because later steps (registry, state, panel,
// admin) each own their own queries against these tables; Store itself only
// owns opening the connection and running the migration. Clock is exported
// so a test can swap in clock.NewFake before calling a method that stamps a
// row with the current time (e.g. SetAdmin), without Open itself taking a
// Clock parameter — Open's signature is a cross-package contract (spec §3)
// that other steps already build against.
type Store struct {
	DB    *gorm.DB
	Clock clock.Clock
}

// models lists every table this step owns (spec §3), in the order
// AutoMigrate should create them: tables a foreign key could point at (none
// declare one in v1 — the registry is stitched together by string ids, not
// SQL foreign keys, so a mon-client can be deleted independently of its
// history) come first, but the order below is otherwise just the spec's own
// table order.
func models() []any {
	return []any{
		&Setting{},
		&Admin{},
		&AdminSession{},
		&LoginAttempt{},
		&RegistrationRequest{},
		&MonClient{},
		&Target{},
		&PanelInbound{},
		&ClientConfig{},
		&EventOutbox{},
		&StatsBucket{},
		&ProbeSeen{},
		&Sweep{},
	}
}

// Open opens the SQLite file at path — or any DSN gorm's sqlite driver
// accepts, including ":memory:" or a t.TempDir() path in tests — with the
// pragmas spec §3 fixes: foreign keys on and a 5s busy timeout so a writer
// waits instead of failing under the single-writer pattern below, then
// migrates it. A caller never needs to call Migrate itself; Open always
// leaves the schema current. For a real file path (anything but ":memory:"),
// Open also creates the file's parent directory first: sqlite happily
// creates the database file itself but not the directory it lives in, so a
// fresh install whose dataDir does not exist yet would otherwise fail on the
// very first `admin set` or `run`.
//
// The file holds monToken and tgToken, so Open also keeps it private
// (decision #52 §5): the directory is created 0700 and, on every open, set
// to 0700 with the database file set to 0600. Doing it on every open rather
// than only at creation is what repairs an install whose directory or file
// were created looser (umask, an older build, a StateDirectory default).
// certmagic's dataDir/certs is already 0700/0600 by its own FileStorage.
func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
			return nil, fmt.Errorf("store: data dir for %s: %w", path, err)
		}
	}

	dsn := path
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	dsn = fmt.Sprintf("%s%s_foreign_keys=on&_busy_timeout=5000", path, sep)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("store: underlying sql.DB: %w", err)
	}
	// mattn/go-sqlite3 serialises writers itself; a second connection only
	// buys us "database is locked" under our own busy_timeout instead of a
	// clean queue. One connection for the whole process is deliberate, not
	// an oversight (spec §3: "одно соединение на запись").
	sqlDB.SetMaxOpenConns(1)

	s := &Store{DB: db, Clock: clock.Real{}}
	if err := s.Migrate(); err != nil {
		return nil, err
	}
	// Migrate has touched the database, so sqlite has created the file by
	// now if it did not exist; tighten it whether new or old.
	if path != ":memory:" {
		file, _, _ := strings.Cut(path, "?")
		if err := os.Chmod(file, privateFileMode); err != nil {
			return nil, fmt.Errorf("store: chmod %s: %w", file, err)
		}
	}
	return s, nil
}

// privateDirMode and privateFileMode are dataDir's and mon-server.db's
// permissions (decision #52 §5, spec §2): owner only.
const (
	privateDirMode  os.FileMode = 0o700
	privateFileMode os.FileMode = 0o600
)

// ensurePrivateDir creates dir (and any missing parents) and sets dir itself
// to privateDirMode, whatever it was before.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, privateDirMode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.Chmod(dir, privateDirMode); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// Migrate brings the schema up to date with every model this step declares,
// then runs the data migrations that go with it (migrateProxyPaths). It is
// idempotent: gorm's AutoMigrate only adds what is missing and a data
// migration finds nothing left to rewrite the second time, so calling
// Migrate again on an already-current database is a fast no-op, which is
// what lets Open call it unconditionally on every process start.
func (s *Store) Migrate() error {
	for _, m := range models() {
		if err := s.DB.AutoMigrate(m); err != nil {
			return fmt.Errorf("store: migrate %T: %w", m, err)
		}
	}
	return s.migrateProxyPaths()
}
