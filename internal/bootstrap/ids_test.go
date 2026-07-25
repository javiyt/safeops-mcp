package bootstrap

import (
	"strings"
	"testing"
)

func TestCryptoGenerators(t *testing.T) {
	id, err := (CryptoIDGenerator{}).NewID("apr")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "apr_") {
		t.Fatalf("id = %q", id)
	}
	code, err := (CryptoCodeGenerator{}).NewCode(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 4 {
		t.Fatalf("code = %q", code)
	}
	if _, err := (CryptoCodeGenerator{}).NewCode(0); err == nil {
		t.Fatal("NewCode() error = nil, want invalid digits error")
	}
	if (SystemClock{}).Now().IsZero() {
		t.Fatal("Now() returned zero time")
	}
}
