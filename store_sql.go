package tinkrotate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
)

var _ ManagedStore = (*SQLStore)(nil)

// SQLStore implements the Store interface using a relational database via database/sql.
// It assumes a simple schema with one row per managed keyset.
type SQLStore struct {
	db        *sql.DB
	kek       tink.AEAD // Optional: Key-Encryption-Key for encrypting the keyset handle data
	tableName string    // Name of the database table
	dialect   string    // SQL dialect (e.g., "sqlite", "mysql", "postgres")
}

// SQLStoreOptions holds configuration options for SQLStore.
type SQLStoreOptions struct {
	// KEK is an optional Tink AEAD primitive to encrypt/decrypt the keyset data.
	KEK tink.AEAD
	// TableName specifies the name of the database table (default: "tink_keysets").
	TableName string
	// Dialect specifies the SQL dialect (e.g., "sqlite", "mysql", "postgres").
	// Defaults to "sqlite" if empty.
	Dialect string
}

// NewSQLStore creates a new SQLStore instance.
// db: An initialized *sql.DB connection pool.
// opts: Optional configuration settings. If nil, defaults will be used.
func NewSQLStore(db *sql.DB, opts *SQLStoreOptions) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("sql database connection cannot be nil")
	}

	s := &SQLStore{
		db:        db,
		tableName: "tink_keysets", // Default table name
		dialect:   "sqlite",       // Default dialect
	}

	if opts != nil {
		if opts.TableName != "" {
			s.tableName = opts.TableName
		}
		if opts.KEK != nil {
			s.kek = opts.KEK
		}
		if opts.Dialect != "" {
			s.dialect = strings.ToLower(opts.Dialect)
		}
	}

	if s.kek == nil {
		slog.Warn("SQLStore created without KEK, keyset data will be stored unencrypted.")
	}

	return s, nil
}

// Schema returns a basic schema suggestion for the table used by SQLStore.
// Adjust types (BLOB, INTEGER) based on your specific SQL dialect.
// The 'id' column stores the unique keysetName.
func (s *SQLStore) Schema() string {
	dataType := "BLOB"
	if s.dialect == "postgres" {
		dataType = "BYTEA"
	}

	// TODO: Consider dialect for INTEGER type as well (e.g., SERIAL for postgres auto-increment?)
	// For now, sticking with standard INTEGER.
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
    id VARCHAR(255) PRIMARY KEY,
    keyset_data %s NOT NULL,
    metadata_data %s NOT NULL,
    version INTEGER NOT NULL
);`, s.tableName, dataType, dataType)
}

// rebind replaces the SQL query's parameter placeholders based on the dialect.
// Uses '?' for most dialects and '$1', '$2', etc. for PostgreSQL.
func rebind(dialect string, query string) string {
	if dialect == "postgres" {
		q := []byte(query)
		n := 0
		for i := 0; i < len(q); i++ {
			if q[i] == '?' {
				n++
				q = append(q[:i], append([]byte(fmt.Sprintf("$%d", n)), q[i+1:]...)...)
			}
		}
		return string(q)
	}
	// Keep '?' for other dialects (like sqlite, mysql)
	return query
}

// ReadKeysetAndMetadata implements the ManagedStore interface.
func (s *SQLStore) ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*ReadResult, error) {
	rawQuery := fmt.Sprintf("SELECT %s, %s, %s FROM %s WHERE %s = ?",
		"keyset_data", "metadata_data", "version", s.tableName, "id")
	query := rebind(s.dialect, rawQuery)

	var keysetData, metadataData []byte
	var version int64

	row := s.db.QueryRowContext(ctx, query, keysetName)
	err := row.Scan(&keysetData, &metadataData, &version)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &ReadResult{Context: int64(0)}, ErrKeysetNotFound
		}
		return nil, fmt.Errorf("failed to query keyset row: %w", err)
	}

	if s.kek != nil {
		decryptedKeysetData, err := s.kek.Decrypt(keysetData, []byte(keysetName))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt keyset data for '%s': %w", keysetName, err)
		}
		keysetData = decryptedKeysetData
	}

	var handle *keyset.Handle
	reader := keyset.NewBinaryReader(bytes.NewReader(keysetData))
	if s.kek != nil {
		handle, err = keyset.ReadWithAssociatedData(reader, s.kek, []byte(keysetName))
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted keyset handle for '%s': %w", keysetName, err)
		}
	} else {
		handle, err = insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read cleartext keyset handle for '%s': %w", keysetName, err)
		}
	}

	metadata := &tinkrotatev1.KeyRotationMetadata{}
	err = proto.Unmarshal(metadataData, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata protobuf for '%s': %w", keysetName, err)
	}

	return &ReadResult{
		Handle:   handle,
		Metadata: metadata,
		Context:  version,
	}, nil
}

// WriteKeysetAndMetadata implements the ManagedStore interface.
func (s *SQLStore) WriteKeysetAndMetadata(ctx context.Context, keysetName string, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext any) error {
	if handle == nil || metadata == nil {
		return errors.New("handle and metadata cannot be nil for writing")
	}

	var expectedVersion int64
	isInsert := false
	if expectedContext == nil {
		isInsert = true
		expectedVersion = 0
	} else {
		v, ok := expectedContext.(int64)
		if !ok {
			return fmt.Errorf("invalid expectedContext type: expected int64, got %T", expectedContext)
		}
		if v == 0 {
			isInsert = true
		}
		expectedVersion = v
	}

	metadataData, err := proto.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata protobuf: %w", err)
	}

	keysetBuf := new(bytes.Buffer)
	if s.kek != nil {
		writer := keyset.NewBinaryWriter(keysetBuf)
		err = handle.WriteWithAssociatedData(writer, s.kek, []byte(keysetName))
		if err != nil {
			return fmt.Errorf("failed to write encrypted keyset handle for '%s': %w", keysetName, err)
		}
	} else {
		if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(keysetBuf)); err != nil {
			return fmt.Errorf("failed to write cleartext keyset handle for '%s': %w", keysetName, err)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var res sql.Result
	if isInsert {
		rawQuery := fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s) VALUES (?, ?, ?, ?)",
			s.tableName, "id", "keyset_data", "metadata_data", "version")
		query := rebind(s.dialect, rawQuery)
		newVersion := int64(1)
		res, err = tx.ExecContext(ctx, query, keysetName, keysetBuf.Bytes(), metadataData, newVersion)
		if err != nil {
			return fmt.Errorf("failed to insert keyset row for '%s': %w", keysetName, err)
		}
	} else {
		rawQuery := fmt.Sprintf("UPDATE %s SET %s = ?, %s = ?, %s = ? WHERE %s = ? AND %s = ?",
			s.tableName, "keyset_data", "metadata_data", "version", "id", "version")
		query := rebind(s.dialect, rawQuery)
		newVersion := expectedVersion + 1
		res, err = tx.ExecContext(ctx, query, keysetBuf.Bytes(), metadataData, newVersion, keysetName, expectedVersion)
		if err != nil {
			return fmt.Errorf("failed to update keyset row for '%s': %w", keysetName, err)
		}
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrOptimisticLockFailed
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ForEachKeyset implements the ManagedStore interface. It does not perform any
// paging, all rows are retrieved and iterated over at once.
func (s *SQLStore) ForEachKeyset(ctx context.Context, fn func(keysetName string) error) error {
	query := fmt.Sprintf("SELECT DISTINCT %s FROM %s", "id", s.tableName)

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query distinct keyset names: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var keysetNames []string

	for rows.Next() {
		var keysetName string
		if err := rows.Scan(&keysetName); err != nil {
			return fmt.Errorf("failed to scan keyset name: %w", err)
		}
		keysetNames = append(keysetNames, keysetName)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		// Check for errors during iteration
		return fmt.Errorf("error during keyset name iteration: %w", err)
	}

	for _, keysetName := range keysetNames {
		if err := fn(keysetName); err != nil {
			// If the callback function returns an error, stop iteration and return it.
			return fmt.Errorf("callback function failed for keyset '%s': %w", keysetName, err)
		}
	}

	return nil
}

// GetCurrentHandle implements the Store interface.
func (s *SQLStore) GetCurrentHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	rawQuery := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ?",
		"keyset_data", "version", s.tableName, "id") // Select keyset_data and version
	query := rebind(s.dialect, rawQuery)

	var keysetData []byte
	var version int64 // Need version for KEK associated data consistency

	row := s.db.QueryRowContext(ctx, query, keysetName)
	err := row.Scan(&keysetData, &version)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("keyset '%s': %w", keysetName, ErrKeysetNotFound)
		}
		return nil, fmt.Errorf("failed to query keyset data for '%s': %w", keysetName, err)
	}

	// Decrypt keyset data if KEK is configured
	if s.kek != nil {
		decryptedKeysetData, err := s.kek.Decrypt(keysetData, []byte(keysetName)) // Use keysetName as associated data
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt keyset data for '%s': %w", keysetName, err)
		}
		keysetData = decryptedKeysetData
	}

	// Read the handle
	var handle *keyset.Handle
	reader := keyset.NewBinaryReader(bytes.NewReader(keysetData))
	if s.kek != nil {
		// Must use ReadWithAssociatedData if KEK was used for writing/decryption
		handle, err = keyset.ReadWithAssociatedData(reader, s.kek, []byte(keysetName))
		if err != nil {
			return nil, fmt.Errorf("failed to read encrypted keyset handle for '%s': %w", keysetName, err)
		}
	} else {
		handle, err = insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read cleartext keyset handle for '%s': %w", keysetName, err)
		}
	}

	return handle, nil
}

// GetPublicKeySetHandle implements the Store interface.
func (s *SQLStore) GetPublicKeySetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	privateHandle, err := s.GetCurrentHandle(ctx, keysetName)
	if err != nil {
		// Error from GetCurrentHandle already includes context (e.g., ErrKeysetNotFound)
		return nil, err
	}

	// Get the public handle
	publicHandle, err := privateHandle.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public handle for keyset '%s': %w", keysetName, err)
	}

	return publicHandle, nil
}
