package tinkrotate

import "database/sql"

type ctxKeyOrigKeyset = struct{}
type ctxKeyOrigMetadata = struct{}

type SQLDialect struct {
	GetKeysetQuery    string
	UpdateKeysetQuery string
}

var SQLiteDialect = SQLDialect{
	GetKeysetQuery:    `select`,
	UpdateKeysetQuery: `update`,
}

type SQLStore struct {
	db      *sql.DB
	dialect SQLDialect
}

func NewSQLStore(db *sql.DB, dialect SQLDialect, keysetID string) *SQLStore {
	return &SQLStore{}
}

func (s *SQLStore) Initialize() error {
	return nil
}
