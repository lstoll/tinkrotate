package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"google.golang.org/protobuf/proto"
	"lds.li/tinkrotate"
	tinkrotatev1 "lds.li/tinkrotate/proto/tinkrotate/v1"
)

var _ tinkrotate.ManagedStore = (*SQLStore)(nil)

type SQLDialect int

const (
	SQLDialectSQLite SQLDialect = iota + 1
	SQLDialectMySQL
	SQLDialectPostgreSQL
)

type SQLStore struct {
	db        *sql.DB
	kek       tink.AEAD
	tableName string
	dialect   SQLDialect
}

type SQLStoreOptions struct {
	KEK       tink.AEAD
	TableName string
	Dialect   SQLDialect
}

func NewSQLStore(db *sql.DB, opts *SQLStoreOptions) (*SQLStore, error) {
	if db == nil {
		return nil, errors.New("sql database connection cannot be nil")
	}

	s := &SQLStore{
		db:        db,
		tableName: "tink_keysets",
		dialect:   SQLDialectSQLite,
	}

	if opts != nil {
		if opts.TableName != "" {
			s.tableName = opts.TableName
		}
		if opts.KEK != nil {
			s.kek = opts.KEK
		}
		if opts.Dialect != SQLDialect(0) {
			s.dialect = opts.Dialect
		}
	}

	if s.kek == nil {
		slog.Warn("SQLStore created without KEK, keyset data will be stored unencrypted.")
	}

	return s, nil
}

func (s *SQLStore) Schema() string {
	dataType := "BLOB"
	if s.dialect == SQLDialectPostgreSQL {
		dataType = "BYTEA"
	}

	return fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
    id VARCHAR(255) PRIMARY KEY,
    keyset_data %s NOT NULL,
    metadata_data %s NOT NULL,
    version INTEGER NOT NULL
);`, s.tableName, dataType, dataType)
}

func rebind(dialect SQLDialect, query string) string {
	if dialect == SQLDialectPostgreSQL {
		var n int
		re := regexp.MustCompile(`\?`)
		query = re.ReplaceAllStringFunc(query, func(_ string) string {
			n++
			return fmt.Sprintf("$%d", n)
		})
		return query
	}
	return query
}

func (s *SQLStore) ReadKeysetAndMetadata(ctx context.Context, keysetName string) (*tinkrotate.ReadResult, error) {
	rawQuery := fmt.Sprintf("SELECT %s, %s, %s FROM %s WHERE %s = ?",
		"keyset_data", "metadata_data", "version", s.tableName, "id")
	query := rebind(s.dialect, rawQuery)

	var keysetData, metadataData []byte
	var version int64

	row := s.db.QueryRowContext(ctx, query, keysetName)
	err := row.Scan(&keysetData, &metadataData, &version)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &tinkrotate.ReadResult{Context: int64(0)}, tinkrotate.ErrKeysetNotFound
		}
		return nil, fmt.Errorf("failed to query keyset row: %w", err)
	}

	handle, err := s.decryptAndParseHandle(keysetData, keysetName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyset handle for '%s': %w", keysetName, err)
	}

	metadata := &tinkrotatev1.KeyRotationMetadata{}
	err = proto.Unmarshal(metadataData, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata protobuf for '%s': %w", keysetName, err)
	}

	return &tinkrotate.ReadResult{
		Handle:   handle,
		Metadata: metadata,
		Context:  version,
	}, nil
}

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
		return tinkrotate.ErrOptimisticLockFailed
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

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
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error during keyset name iteration: %w", err)
	}
	_ = rows.Close()

	for _, keysetName := range keysetNames {
		if err := fn(keysetName); err != nil {
			return fmt.Errorf("callback function failed for keyset '%s': %w", keysetName, err)
		}
	}

	return nil
}

func (s *SQLStore) GetHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	rawQuery := fmt.Sprintf("SELECT %s, %s FROM %s WHERE %s = ?",
		"keyset_data", "version", s.tableName, "id")
	query := rebind(s.dialect, rawQuery)

	var keysetData []byte
	var version int64

	row := s.db.QueryRowContext(ctx, query, keysetName)
	err := row.Scan(&keysetData, &version)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("keyset '%s': %w", keysetName, tinkrotate.ErrKeysetNotFound)
		}
		return nil, fmt.Errorf("failed to query keyset data for '%s': %w", keysetName, err)
	}

	handle, err := s.decryptAndParseHandle(keysetData, keysetName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keyset handle for '%s': %w", keysetName, err)
	}

	return handle, nil
}

func (s *SQLStore) GetPublicHandle(ctx context.Context, keysetName string) (*keyset.Handle, error) {
	privateHandle, err := s.GetHandle(ctx, keysetName)
	if err != nil {
		return nil, err
	}

	publicHandle, err := privateHandle.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to get public handle for keyset '%s': %w", keysetName, err)
	}

	return publicHandle, nil
}

func (s *SQLStore) decryptAndParseHandle(keysetData []byte, keysetName string) (*keyset.Handle, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(keysetData))
	if s.kek != nil {
		return keyset.ReadWithAssociatedData(reader, s.kek, []byte(keysetName))
	}
	return insecurecleartextkeyset.Read(reader)
}
