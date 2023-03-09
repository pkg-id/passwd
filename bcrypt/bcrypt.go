// Package bcrypt provides an implementation of the HashComparer interface using the bcrypt algorithm.
package bcrypt

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

// bcryptImpl is a type that implements the HashComparer interface using the bcrypt algorithm.
type bcryptImpl int

// Hash generates a bcrypt hash from the specified plaintext password using the configured cost.
// It returns the resulting hash as a string and any errors that occur during the hash generation.
func (b bcryptImpl) Hash(plain string) (string, error) {
	switch b {
	default:
		return "", fmt.Errorf("passwd: bcryptImpl: hash: unsuported cost")
	case DefaultCost:
		b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
		return string(b), err
	}
}

// Compare compares the specified plaintext password with the specified bcrypt hash.
// It returns an error if the comparison fails.
func (b bcryptImpl) Compare(hash string, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}

// DefaultCost is a bcrypt algorithm with default cost.
const DefaultCost = bcryptImpl(1)
