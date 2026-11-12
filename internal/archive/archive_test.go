package archive

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jd869/debhash/internal/debtest"
	"github.com/jd869/debhash/internal/keyring"
)

const releaseText = "Origin: Ubuntu\nVersion: 24.04\nSuite: noble\nSHA256:\n 0000000000000000000000000000000000000000000000000000000000000000 12 main/binary-arm64/Packages.gz\n"

func serve(t *testing.T, files map[string][]byte) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestReleaseVerifiesInRelease(t *testing.T) {
	key := debtest.SigningKey(t)
	url := serve(t, map[string][]byte{"dists/noble/InRelease": debtest.ClearSign(t, key, []byte(releaseText))})
	rel, err := Repo{Mirror: url, Keyring: debtest.Keyring(key)}.Release(context.Background(), "noble")
	if err != nil {
		t.Fatal(err)
	}
	if rel.Version != "24.04" || len(rel.Files) != 1 || !strings.Contains(rel.SignedBy, "Test Archive Signing Key") {
		t.Fatalf("release = %+v", rel)
	}
}

func TestReleaseRejectsTamperedInRelease(t *testing.T) {
	key := debtest.SigningKey(t)
	signed := debtest.ClearSign(t, key, []byte(releaseText))
	// Swap the index digest after signing, as a malicious mirror would.
	tampered := bytes.Replace(signed, []byte("0000000000"), []byte("1111111111"), 1)
	url := serve(t, map[string][]byte{"dists/noble/InRelease": tampered})
	_, err := Repo{Mirror: url, Keyring: debtest.Keyring(key)}.Release(context.Background(), "noble")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestReleaseRejectsUnknownKey(t *testing.T) {
	other, err := debtest.NewKey("Someone Else")
	if err != nil {
		t.Fatal(err)
	}
	url := serve(t, map[string][]byte{"dists/noble/InRelease": debtest.ClearSign(t, other, []byte(releaseText))})
	_, err = Repo{Mirror: url, Keyring: debtest.Keyring(debtest.SigningKey(t))}.Release(context.Background(), "noble")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature for a key not in the keyring, got %v", err)
	}
	// The real Ubuntu keyring must not accept it either.
	ubuntu, err := keyring.Ubuntu()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Repo{Mirror: url, Keyring: ubuntu}).Release(context.Background(), "noble"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Ubuntu keyring accepted a foreign signature: %v", err)
	}
}

func TestReleaseRejectsUnsignedInRelease(t *testing.T) {
	url := serve(t, map[string][]byte{"dists/noble/InRelease": []byte(releaseText)})
	_, err := Repo{Mirror: url, Keyring: debtest.Keyring(debtest.SigningKey(t))}.Release(context.Background(), "noble")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestReleaseFallsBackToDetachedSignature(t *testing.T) {
	key := debtest.SigningKey(t)
	url := serve(t, map[string][]byte{
		"dists/noble/Release":     []byte(releaseText),
		"dists/noble/Release.gpg": debtest.DetachSign(t, key, []byte(releaseText)),
	})
	rel, err := Repo{Mirror: url, Keyring: debtest.Keyring(key)}.Release(context.Background(), "noble")
	if err != nil || rel.Version != "24.04" || rel.SignedBy == "" {
		t.Fatalf("release = %+v, %v", rel, err)
	}

	// Release without its signature is refused.
	unsigned := serve(t, map[string][]byte{"dists/noble/Release": []byte(releaseText)})
	if _, err := (Repo{Mirror: unsigned, Keyring: debtest.Keyring(key)}).Release(context.Background(), "noble"); err == nil {
		t.Fatal("Release without InRelease or Release.gpg must be refused")
	}
}

func TestReleaseNeedsKeyringUnlessNoVerify(t *testing.T) {
	url := serve(t, map[string][]byte{"dists/noble/Release": []byte(releaseText)})
	if _, err := (Repo{Mirror: url}).Release(context.Background(), "noble"); err == nil {
		t.Fatal("no keyring and no NoVerify must be an error")
	}
	rel, err := Repo{Mirror: url, NoVerify: true}.Release(context.Background(), "noble")
	if err != nil || rel.SignedBy != "" || rel.Version != "24.04" {
		t.Fatalf("NoVerify release = %+v, %v", rel, err)
	}
}

// TestRealUbuntuInRelease verifies the live Ubuntu ports archive against the
// embedded keyring. It needs the network, so it only runs when
// DEBHASH_NETWORK_TESTS=1.
func TestRealUbuntuInRelease(t *testing.T) {
	if os.Getenv("DEBHASH_NETWORK_TESTS") != "1" {
		t.Skip("set DEBHASH_NETWORK_TESTS=1 to run against ports.ubuntu.com")
	}
	ubuntu, err := keyring.Ubuntu()
	if err != nil {
		t.Fatal(err)
	}
	for _, suite := range []string{"noble", "noble-updates", "noble-security"} {
		rel, err := Repo{Mirror: "http://ports.ubuntu.com/ubuntu-ports", Keyring: ubuntu}.Release(context.Background(), suite)
		if err != nil {
			t.Fatalf("%s: %v", suite, err)
		}
		if rel.Origin != "Ubuntu" || len(rel.Files) == 0 {
			t.Fatalf("%s: release = %+v", suite, rel)
		}
		t.Logf("%s: %d index files, signed by %s", suite, len(rel.Files), rel.SignedBy)
	}
}
