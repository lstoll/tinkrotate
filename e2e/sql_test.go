package e2e

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql" // Import the mysql driver
	_ "github.com/jackc/pgx/v5/stdlib" // Import the pgx driver for PostgreSQL
	"github.com/lstoll/tinkrotate"
	_ "github.com/mattn/go-sqlite3" // Import the sqlite3 driver
)

func TestAutoRotator_SQLite_BlackBox(t *testing.T) {
	// --- Database Setup ---
	// Using ":memory:" for a private in-memory database per test run
	// Use cache=shared to ensure all connections see the same in-memory DB
	db, err := sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Failed to open in-memory sqlite db: %v", err)
	}
	defer db.Close()

	// --- Store Setup ---
	// Pass nil for options to use defaults (table name = "tink_keysets", no KEK)
	sqlStore, err := tinkrotate.NewSQLStore(db, &tinkrotate.SQLStoreOptions{Dialect: tinkrotate.SQLDialectSQLite})
	if err != nil {
		t.Fatalf("Failed to create SQLStore: %v", err)
	}

	// Create Schema
	_, err = db.Exec(sqlStore.Schema())
	if err != nil {
		t.Fatalf("Failed to create database schema: %v", err)
	}

	// Call the central runStoreTest function from store_test.go
	runStoreTest(t, sqlStore)
}

func TestAutoRotator_MySQL_BlackBox(t *testing.T) {
	mysqlURL := os.Getenv("TINKROTATE_MYSQL_URL")
	if mysqlURL == "" {
		t.Skip("TINKROTATE_MYSQL_URL not set, skipping MySQL test")
	}

	// --- Database Setup ---
	db, err := sql.Open("mysql", mysqlURL)
	if err != nil {
		t.Fatalf("Failed to open mysql db: %v", err)
	}
	defer db.Close()

	// --- Store Setup ---
	sqlStore, err := tinkrotate.NewSQLStore(db, &tinkrotate.SQLStoreOptions{Dialect: tinkrotate.SQLDialectMySQL})
	if err != nil {
		t.Fatalf("Failed to create SQLStore: %v", err)
	}

	// Create Schema
	_, err = db.Exec(sqlStore.Schema())
	if err != nil {
		t.Fatalf("Failed to create database schema: %v", err)
	}

	// Call the central runStoreTest function
	runStoreTest(t, sqlStore)
}

func TestAutoRotator_Postgres_BlackBox(t *testing.T) {
	postgresURL := os.Getenv("TINKROTATE_POSTGRES_URL")
	if postgresURL == "" {
		t.Skip("TINKROTATE_POSTGRES_URL not set, skipping PostgreSQL test")
	}

	// --- Database Setup ---
	db, err := sql.Open("pgx", postgresURL) // Use "pgx" driver name
	if err != nil {
		t.Fatalf("Failed to open postgres db: %v", err)
	}
	defer db.Close()

	// --- Store Setup ---
	sqlStore, err := tinkrotate.NewSQLStore(db, &tinkrotate.SQLStoreOptions{Dialect: tinkrotate.SQLDialectPostgreSQL})
	if err != nil {
		t.Fatalf("Failed to create SQLStore: %v", err)
	}

	// Create Schema
	_, err = db.Exec(sqlStore.Schema())
	if err != nil {
		t.Fatalf("Failed to create database schema: %v", err)
	}

	// Call the central runStoreTest function
	runStoreTest(t, sqlStore)
}
