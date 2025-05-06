#!/usr/bin/env bash
set -euo pipefail

MINIO_ADDR=http://localhost:9000
MINIO_ACCESS_KEY=minio
MINIO_SECRET_KEY=minio123
TINKROTATE_POSTGRES_URL="postgres://test_user:test_password@localhost:5438/test_db"
TINKROTATE_MYSQL_URL="test_user:test_password@tcp(localhost:3308)/test_db?tls=skip-verify"

export MINIO_ADDR
export MINIO_ACCESS_KEY
export MINIO_SECRET_KEY
export TINKROTATE_POSTGRES_URL
export TINKROTATE_MYSQL_URL

go test . "$@"
