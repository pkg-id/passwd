// Package passwd provides a secure way to manage passwords in Go without requiring any additional setup.
// The Password type is used just like a normal string, but provides additional functionality such as hashing and
// comparing passwords securely.
package passwd

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/pkg-id/passwd/bcrypt"
	"sync"
)

// HashComparer is a contract for the hashing algorithm that can generate and compare hashes.
// To provide a custom implementation use the SetHashComparer function.
type HashComparer interface {
	// Hash generates a hash from the specified plaintext password using the configured algorithm.
	// It returns the resulting hash as a string and any errors that occur during the hash generation.
	Hash(plain string) (string, error)

	// Compare compares the specified plaintext password with the specified hash.
	// It returns an error if the comparison fails.
	Compare(hash string, plain string) error
}

// hashComparer is a global variable that represents the current hash algorithm used for hashing and comparing passwords.
// By default, hashComparer is set to the bcrypt algorithm with the default cost.
var hashComparer HashComparer = bcrypt.DefaultCost
var lock sync.RWMutex

// SetHashComparer sets the global hash comparer to the specified value.
// This function is concurrent-safe.
func SetHashComparer(hc HashComparer) {
	lock.Lock()
	defer lock.Unlock()
	hashComparer = hc
}

// Password is a type that represents a password.
// It provides additional functionality for securely hashing and comparing passwords.
type Password string

// Value implements the driver.Valuer interface. It generates a hash from the password and returns the hash value.
// It returns an error if the hash generation fails.
func (p Password) Value() (driver.Value, error) {
	hash, err := hashComparer.Hash(string(p))
	if err != nil {
		return nil, fmt.Errorf("passwd: Password.Value: generate hash: %w", err)
	}
	return driver.Value(hash), nil
}

// Scan implements the sql.Scanner interface. It sets the password value to an empty string if the source value is nil.
// Otherwise, it sets the password value to the source value.
func (p *Password) Scan(src any) error {
	if src == nil {
		*p = ""
		return nil
	}
	var sv Password
	switch tv := src.(type) {
	default:
		return fmt.Errorf("passwd: Scan: unsuported source type: %T", tv)
	case string:
		sv = Password(tv)
	case []byte:
		sv = Password(tv)
	}
	*p = sv
	return nil
}

// Compare compares the password with plain text. It returns an error if the comparison fails.
func (p Password) Compare(plain string) error {
	return hashComparer.Compare(string(p), plain)
}

// String returns a string representation of the password. It hides the actual password value by returning "FILTERED".
func (p Password) String() string {
	return "FILTERED"
}

// MarshalJSON returns the JSON encoding of the password. It hides the actual password value by returning "FILTERED".
func (p Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}
