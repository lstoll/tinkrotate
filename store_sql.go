package tinkrotate

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	tinkrotatev1 "github.com/lstoll/tinkrotate/proto/tinkrotate/v1"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
)

// SQLStore implements the Store interface using a relational database via database/sql.
// It assumes a simple schema with one row per managed keyset.
type SQLStore struct {
	db          *sql.DB
	keysetID    string    // Identifier for the keyset row in the table
	kek         tink.AEAD // Optional: Key-Encryption-Key for encrypting the keyset handle data
	tableName   string    // Name of the database table
	idCol       string    // Name of the ID column
	keysetCol   string    // Name of the keyset data column (BLOB)
	metadataCol string    // Name of the metadata column (BLOB)
	versionCol  string    // Name of the version column (INTEGER)
}

// SQLStoreOption is used to configure SQLStore.
type SQLStoreOption func(*SQLStore)

// WithSQLTableName sets the table name (default: "tink_keysets").
func WithSQLTableName(name string) SQLStoreOption {
	return func(s *SQLStore) {
		s.tableName = name
	}
}

// WithSQLColumnNames sets custom column names.
func WithSQLColumnNames(id, keyset, metadata, version string) SQLStoreOption {
	return func(s *SQLStore) {
		s.idCol = id
		s.keysetCol = keyset
		s.metadataCol = metadata
		s.versionCol = version
	}
}

// WithSQLKEK provides a Tink AEAD primitive to encrypt/decrypt the keyset data.
func WithSQLKEK(kek tink.AEAD) SQLStoreOption {
	return func(s *SQLStore) {
		s.kek = kek
	}
}

// NewSQLStore creates a new SQLStore instance.
// db: An initialized *sql.DB connection pool.
// keysetID: A unique identifier for the keyset row managed by this store instance.
func NewSQLStore(db *sql.DB, keysetID string, opts ...SQLStoreOption) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("sql database connection cannot be nil")
	}
	if keysetID == "" {
		return nil, errors.New("keysetID cannot be empty")
	}

	s := &SQLStore{
		db:          db,
		keysetID:    keysetID,
		tableName:   "tink_keysets", // Default table name
		idCol:       "id",           // Default column names
		keysetCol:   "keyset_data",
		metadataCol: "metadata_data",
		versionCol:  "version",
	}

	for _, opt := range opts {
		opt(s)
	}

	// Basic validation that KEK is provided if needed (optional)
	// if s.kek == nil {
	//  log.Println("Warning: SQLStore created without KEK, keyset data will be stored unencrypted.")
	// }

	return s, nil
}

// Schema returns a basic schema suggestion for the table used by SQLStore.
// Adjust types (BLOB, INTEGER) based on your specific SQL dialect.
func (s *SQLStore) Schema() string {
	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
    %s VARCHAR(255) PRIMARY KEY,
    %s BLOB NOT NULL,
    %s BLOB NOT NULL,
    %s INTEGER NOT NULL
);`, s.tableName, s.idCol, s.keysetCol, s.metadataCol, s.versionCol)
}

// ReadKeysetAndMetadata implements the Store interface.
func (s *SQLStore) ReadKeysetAndMetadata(ctx context.Context) (*ReadResult, error) {
	query := fmt.Sprintf("SELECT %s, %s, %s FROM %s WHERE %s = ?",
		s.keysetCol, s.metadataCol, s.versionCol, s.tableName, s.idCol)

	var keysetData, metadataData []byte
	var version int64 // Use int64 for version

	row := s.db.QueryRowContext(ctx, query, s.keysetID)
	err := row.Scan(&keysetData, &metadataData, &version)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return version 0 in context to indicate non-existence for Write operation
			return &ReadResult{Context: int64(0)}, ErrKeysetNotFound
		}
		return nil, fmt.Errorf("failed to query keyset row: %w", err)
	}

	// Decrypt keyset data if KEK is configured
	if s.kek != nil {
		decryptedKeysetData, err := s.kek.Decrypt(keysetData, []byte(s.keysetID)) // Use keysetID as associated data
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt keyset data: %w", err)
		}
		keysetData = decryptedKeysetData
	}

	var handle *keyset.Handle
	reader := keyset.NewBinaryReader(bytes.NewReader(keysetData))
	if s.kek != nil {
		handle, err = keyset.ReadWithAssociatedData(reader, s.kek, []byte(s.keysetID))
		if err != nil {
			return nil, fmt.Errorf("failed to read keyset handle: %w", err)
		}
	} else {
		handle, err = insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read keyset handle: %w", err)
		}
	}

	// Parse metadata
	metadata := &tinkrotatev1.KeyRotationMetadata{}
	err = proto.Unmarshal(metadataData, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata protobuf: %w", err)
	}

	// Return data and the version read as context
	return &ReadResult{
		Handle:   handle,
		Metadata: metadata,
		Context:  version,
	}, nil
}

// WriteKeysetAndMetadata implements the Store interface.
func (s *SQLStore) WriteKeysetAndMetadata(ctx context.Context, handle *keyset.Handle, metadata *tinkrotatev1.KeyRotationMetadata, expectedContext interface{}) error {
	if handle == nil || metadata == nil {
		return errors.New("handle and metadata cannot be nil for writing")
	}

	// Determine expected version for optimistic locking
	var expectedVersion int64
	isInsert := false
	if expectedContext == nil {
		// Assume initial write if context is nil
		isInsert = true
		expectedVersion = 0 // For logic below, though not used in INSERT directly
	} else {
		v, ok := expectedContext.(int64)
		if !ok {
			return fmt.Errorf("invalid expectedContext type: expected int64, got %T", expectedContext)
		}
		if v == 0 {
			// Version 0 indicates the record should not exist yet (initial write)
			isInsert = true
		}
		expectedVersion = v
	}

	// Serialize metadata
	metadataData, err := proto.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata protobuf: %w", err)
	}

	// Serialize keyset handle (binary format)
	keysetBuf := new(bytes.Buffer)
	if s.kek != nil {
		writer := keyset.NewBinaryWriter(keysetBuf)
		err = handle.WriteWithAssociatedData(writer, s.kek, []byte(s.keysetID))
		if err != nil {
			return fmt.Errorf("failed to write keyset handle: %w", err)
		}
	} else {
		if err := insecurecleartextkeyset.Write(handle, keyset.NewBinaryWriter(keysetBuf)); err != nil {
			return fmt.Errorf("failed to write keyset handle: %w", err)
		}
	}

	// --- Database Transaction ---
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Rollback if commit doesn't happen

	var res sql.Result
	if isInsert {
		// Initial write (INSERT)
		query := fmt.Sprintf("INSERT INTO %s (%s, %s, %s, %s) VALUES (?, ?, ?, ?)",
			s.tableName, s.idCol, s.keysetCol, s.metadataCol, s.versionCol)
		newVersion := int64(1) // Start versioning at 1
		res, err = tx.ExecContext(ctx, query, s.keysetID, keysetBuf.Bytes(), metadataData, newVersion)
		if err != nil {
			// Handle potential race condition if another process inserted first (e.g., unique constraint violation)
			// This depends heavily on the DB driver and schema constraints.
			// A simple check for existing row before insert might be needed, or rely on constraint violation error.
			return fmt.Errorf("failed to insert keyset row: %w", err)
		}
	} else {
		// Update existing row with optimistic lock check
		query := fmt.Sprintf("UPDATE %s SET %s = ?, %s = ?, %s = ? WHERE %s = ? AND %s = ?",
			s.tableName, s.keysetCol, s.metadataCol, s.versionCol, s.idCol, s.versionCol)
		newVersion := expectedVersion + 1
		res, err = tx.ExecContext(ctx, query, keysetBuf.Bytes(), metadataData, newVersion, s.keysetID, expectedVersion)
		if err != nil {
			return fmt.Errorf("failed to update keyset row: %w", err)
		}
	}

	// Check rows affected for optimistic lock
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// If INSERT failed silently (no error but 0 rows), or UPDATE matched 0 rows.
		// This indicates the optimistic lock failed (either key already existed for INSERT,
		// or version mismatch for UPDATE).
		return ErrOptimisticLockFailed
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
