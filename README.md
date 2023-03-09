# passwd

[![GoDoc](https://godoc.org/github.com/pkg-id/passwd?status.svg)](https://godoc.org/github.com/pkg-id/passwd)
[![Go Report Card](https://goreportcard.com/badge/github.com/pkg-id/passwd)](https://goreportcard.com/report/github.com/pkg-id/passwd)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/pkg-id/passwd/master/LICENSE)

passwd is a zero-setup package for hashing passwords and comparing passwords. This package makes it easy to use `passwd.Password` just like a normal string, but it is secure.

## Features

- Zero-setup, just use `passwd.Password` like a normal string, and it will be hashed automatically when storing to the database.
- Implements sql.Scanner and driver.Valuer interfaces.
- Hide the password when printing and Marshaling to JSON.
- Customizable hash comparer algorithm.

## Installation

```bash
go get github.com/pkg-id/passwd
```

## Usage

Here's an example of how to use passwd with a PostgreSQL database:

```go
package main

import (
	"database/sql"
	"fmt"
	"log"

	"github.com/pkg-id/passwd"
	"github.com/pkg-id/passwd/bcrypt"

	_ "github.com/lib/pq"
)

func main() {
	// Open a connection to the database.
	db, err := sql.Open("postgres", "user=postgres password=postgres dbname=mydb sslmode=disable")
	if err != nil {
		log.Fatalf("open db. error: %v", err)
	}
	defer db.Close()

	// OPTIONAL: Set the hash comparer to bcrypt.
	passwd.SetHashComparer(bcrypt.DefaultCost)

	// Hash the password.
	plain := "pass1234"
	pwd := passwd.Password(plain)

	// Insert the password into the database.
	const insert = "INSERT INTO users(password) VALUES ($1) RETURNING id;"
	var id int64
	err = db.QueryRow(insert, pwd).Scan(&id)
	if err != nil {
		log.Fatalf("query row. error: %v", err)
	}

	// Retrieve the password from the database.
	const query = "SELECT password FROM users WHERE id = $1;"
	var scanned passwd.Password
	err = db.QueryRow(query, id).Scan(&scanned)
	if err != nil {
		log.Fatalf("scan row. error: %v", err)
	}

	// Compare the password.
	err = scanned.Compare(plain)
	if err != nil {
		log.Fatalf("expect password match")
	}

	err = scanned.Compare("must be not match")
	if err == nil {
		log.Fatalf("expect password not match")
	}
}
```

> The `passwd.SetHashComparer` function is optional, since bcrypt is already used as the default hash comparer. However, it can be used to set a different hash comparer if needed.

### How it works

`passwd.Password` is a new type based on the string type, and it is used to represent a password. When a password is stored, it is hashed using the default hash comparer (`bcrypt`). When a password is retrieved from the database, it is compared to the plain text password using the same hash comparer. If the passwords match, no error is returned. If the passwords do not match, an error is returned.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.