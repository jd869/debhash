package debtest

import (
	"bytes"
	"sync"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var (
	keyOnce sync.Once
	key     *openpgp.Entity
	keyErr  error
)

// SigningKey returns a throwaway archive signing key, shared by all tests in
// the process (generating one per test would be slow).
func SigningKey(t testing.TB) *openpgp.Entity {
	t.Helper()
	keyOnce.Do(func() { key, keyErr = NewKey("Test Archive Signing Key") })
	must(t, keyErr)
	return key
}

// NewKey generates a fresh Ed25519 signing key.
func NewKey(name string) (*openpgp.Entity, error) {
	return openpgp.NewEntity(name, "", "archive@example.invalid", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
}

// Keyring returns a keyring holding only e's public key.
func Keyring(e *openpgp.Entity) openpgp.EntityList { return openpgp.EntityList{e} }

// ClearSign returns text as an InRelease-style clear-signed message.
func ClearSign(t testing.TB, e *openpgp.Entity, text []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, e.PrivateKey, nil)
	must(t, err)
	_, err = w.Write(text)
	must(t, err)
	must(t, w.Close())
	return buf.Bytes()
}

// DetachSign returns an armored detached signature (Release.gpg) of text.
func DetachSign(t testing.TB, e *openpgp.Entity, text []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	must(t, openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(text), nil))
	return buf.Bytes()
}
