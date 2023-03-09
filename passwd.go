package passwd

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/pkg-id/passwd/bcrypt"
	"sync"
)

type HashComparer interface {
	Hash(plain string) (string, error)
	Compare(hash string, plain string) error
}

var hashComparer HashComparer = bcrypt.DefaultCost
var lock sync.RWMutex

func SetHashComparer(hc HashComparer) {
	lock.Lock()
	defer lock.Unlock()
	hashComparer = hc
}

type Password string

func (p Password) Value() (driver.Value, error) {
	hash, err := hashComparer.Hash(string(p))
	if err != nil {
		return nil, fmt.Errorf("passwd: Password.Value: generate hash: %w", err)
	}
	return driver.Value(hash), nil
}

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

func (p Password) Compare(plain string) error {
	return hashComparer.Compare(string(p), plain)
}

func (p Password) String() string {
	return "FILTERED"
}

func (p Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}
