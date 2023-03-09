package bcrypt

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

type bcryptImpl int

func (b bcryptImpl) Hash(plain string) (string, error) {
	switch b {
	default:
		return "", fmt.Errorf("passwd: bcryptImpl: hash: unsuported cost")
	case DefaultCost:
		b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
		return string(b), err
	}
}

func (b bcryptImpl) Compare(hash string, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}

const DefaultCost = bcryptImpl(1)
