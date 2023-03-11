package bcrypt_test

import (
	"github.com/pkg-id/passwd"
	"github.com/pkg-id/passwd/bcrypt"
	"testing"
)

func TestBcryptImpl(t *testing.T) {
	impls := []passwd.HashComparer{
		bcrypt.MinCost,
		bcrypt.DefaultCost,
		bcrypt.MinCost,
	}

	const plain = "abc123"

	for _, impl := range impls {
		hash, err := impl.Hash(plain)
		if err != nil {
			t.Fatalf("expect no error; got an error: %v", err)
		}

		if err := impl.Compare(hash, plain); err != nil {
			t.Errorf("expect password is match")
		}
	}
}
