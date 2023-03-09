package passwd

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

type Password string

func (p Password) Value() (driver.Value, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
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
	return bcrypt.CompareHashAndPassword([]byte(p), []byte(plain))
}

func (p Password) String() string {
	return "FILTERED"
}

func (p Password) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}
