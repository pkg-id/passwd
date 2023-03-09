//go:build with_postgres

package passwd_test

import (
	"database/sql"
	_ "github.com/lib/pq"
	"github.com/pkg-id/passwd"
	"testing"
)

func setupPostgres(t *testing.T) *sql.DB {
	db, err := sql.Open("postgres", "user=passwd_test password=passwd_test dbname=passwd_test sslmode=disable")
	if err != nil {
		t.Fatalf("setup: open: %v", err)
	}

	_, err = db.Exec(`create table if not exists users(id serial primary key, password text not null);`)
	if err != nil {
		t.Fatalf("setup: exec: %v", err)
	}

	return db
}

func TestPassword_WithPostgres(t *testing.T) {
	db := setupPostgres(t)
	t.Cleanup(func() {
		_ = db.Close()
	})

	plain := "pass1234"
	pwd := passwd.Password(plain)

	const insert = `INSERT INTO users(password) VALUES ($1) RETURNING id;`

	var id int64
	err := db.QueryRow(insert, pwd).Scan(&id)
	if err != nil {
		t.Fatalf("query row. error: %v", err)
	}

	t.Logf("inserted ok, id: %v", id)

	const query = `SELECT password FROM users WHERE id = $1;`

	var scanned passwd.Password
	err = db.QueryRow(query, id).Scan(&scanned)
	if err != nil {
		t.Fatalf("scan row. error: %v", err)
	}

	t.Logf("scan successfully: %s", scanned)

	err = scanned.Compare(plain)
	if err != nil {
		t.Fatalf("expect password match")
	}

	err = scanned.Compare("must be not match")
	if err == nil {
		t.Fatalf("expect password not match")
	}
}
