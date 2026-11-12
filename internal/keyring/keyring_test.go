package keyring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedUbuntuKeyring(t *testing.T) {
	keys, err := Ubuntu()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, k := range keys {
		have[fmt.Sprintf("%X", k.PrimaryKey.Fingerprint)] = true
	}
	for _, fp := range UbuntuArchiveFingerprints {
		if !have[fp] {
			t.Errorf("embedded keyring is missing archive key %s", fp)
		}
	}
	if d := Describe(keys[0]); !strings.Contains(d, "Ubuntu") {
		t.Errorf("Describe = %q", d)
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.gpg")
	if err := os.WriteFile(path, ubuntuArchive, 0o644); err != nil {
		t.Fatal(err)
	}
	if keys, err := Load(path); err != nil || len(keys) < 2 {
		t.Fatalf("Load = %d keys, %v", len(keys), err)
	}
	bad := filepath.Join(t.TempDir(), "bad.gpg")
	os.WriteFile(bad, []byte("not a keyring"), 0o644)
	if _, err := Load(bad); err == nil {
		t.Fatal("expected error for garbage keyring")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
