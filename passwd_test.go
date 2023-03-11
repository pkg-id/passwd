package passwd_test

import (
	"encoding/json"
	"github.com/pkg-id/passwd"
	passwdBcrypt "github.com/pkg-id/passwd/bcrypt"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"testing"
)

func TestPassword_Value(t *testing.T) {
	passwd.SetHashComparer(passwdBcrypt.DefaultCost)
	pwd := passwd.Password("pass1234")
	value, err := pwd.Value()
	if err != nil {
		t.Errorf("value: expected no error, but got an error: %v", err)
	}

	bytes := []byte(value.(string))
	err = bcrypt.CompareHashAndPassword(bytes, []byte("pass1234"))
	if err != nil {
		t.Errorf("compare: expected no error, but got an error: %v", err)
	}

	err = bcrypt.CompareHashAndPassword(bytes, []byte("pass1235"))
	if err == nil {
		t.Errorf("compare: expected an error")
	}
}

func TestPassword_Scan(t *testing.T) {
	pwd := passwd.Password("pass1234")
	value, err := pwd.Value()
	if err != nil {
		t.Errorf("value: expected no error, but got an error: %v", err)
	}

	src := []byte(value.(string))
	var scanned passwd.Password
	if err := scanned.Scan(src); err != nil {
		t.Errorf("scan: expected no error, but got an error: %v", err)
	}
}

func TestPassword_Scan_WhenNil(t *testing.T) {
	var scanned passwd.Password
	if err := scanned.Scan(nil); err != nil {
		t.Errorf("scan: expected no error, but got an error: %v", err)
	}

	if scanned != "" {
		t.Errorf("scan: expect empty string when given src nil")
	}
}

func TestPassword_Scan_WhenTypeUnsupported(t *testing.T) {
	var scanned passwd.Password
	if err := scanned.Scan(1234); err == nil {
		t.Fatalf("scan: expect an error")
	}
}

func TestPassword_Compare(t *testing.T) {
	pwd := passwd.Password("pass1234")
	value, err := pwd.Value()
	if err != nil {
		t.Errorf("value: expected no error, but got an error: %v", err)
	}

	src := value.(string)
	var scanned passwd.Password
	if err := scanned.Scan(src); err != nil {
		t.Errorf("scan: expected no error, but got an error: %v", err)
	}

	if err := scanned.Compare("pass1234"); err != nil {
		t.Errorf("compare sanned: expected no error, but got an error: %v", err)
	}
}

func TestPassword_MarshalJSON(t *testing.T) {
	pwd := passwd.Password("pass1234")
	b, err := json.Marshal(pwd)
	if err != nil {
		t.Errorf("marshal: expected no error, but got an error: %v", err)
	}

	raw := strings.TrimSpace(string(b))
	if raw != "\"FILTERED\"" {
		t.Errorf("expect FILTERED, but got %s!", raw)
	}
}
