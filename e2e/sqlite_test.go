package e2e

import (
	"database/sql"
	"testing"

	"github.com/lstoll/tinkrotate"
	_ "github.com/mattn/go-sqlite3" // Import the sqlite3 driver
	"github.com/stretchr/testify/require"
)

func TestAutoRotator_SQLite_BlackBox(t *testing.T) {
	keysetID := "test-keyset-autorotator" // ID for the keyset in the DB

	// --- Database Setup ---
	// Using ":memory:" for a private in-memory database per test run
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory sqlite db")
	defer db.Close()

	// --- Store Setup ---
	// Pass nil for options to use defaults (table name = "tink_keysets", no KEK)
	sqlStore, err := tinkrotate.NewSQLStore(db, nil)
	require.NoError(t, err, "Failed to create SQLStore")

	// Create Schema
	_, err = db.Exec(sqlStore.Schema())
	require.NoError(t, err, "Failed to create database schema")

	// Call the central runStoreTest function from store_test.go
	runStoreTest(t, sqlStore, keysetID)
}
