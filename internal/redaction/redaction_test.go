package redaction

import (
	"strings"
	"testing"
)

func TestRedactKnownSecrets(t *testing.T) {
	input := `Authorization: Bearer abc token=one api_key=two password=three https://user:pass@example.test {"secret":"four"}`
	got := Redact(input)
	for _, leaked := range []string{"abc", "one", "two", "three", "user:pass", "four"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("Redact() leaked %q in %q", leaked, got)
		}
	}
}

func TestRedactPureJSON(t *testing.T) {
	got := Redact(`{"nested":{"password":"secret-value"},"safe":"value"}`)
	if strings.Contains(got, "secret-value") || !strings.Contains(got, `"safe":"value"`) {
		t.Fatalf("Redact() = %q", got)
	}
}
