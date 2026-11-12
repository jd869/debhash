// Package keyring provides the OpenPGP keys that sign distro archives.
//
// The Ubuntu archive keyring is embedded, copied from the ubuntu-keyring
// package (/usr/share/keyrings/ubuntu-archive-keyring.gpg, version
// 2023.11.28.1). It holds the two archive signing keys:
//
//	790BC7277767219C42C86F933B4FE6ACC0B21F32  Ubuntu Archive Automatic Signing Key (2012)
//	F6ECB3762474EDA9D21B7022871920D1991BC93C  Ubuntu Archive Automatic Signing Key (2018)
//
// plus the 2012 CD image key. Other distros (Debian) pass their own keyring.
package keyring

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

//go:embed ubuntu-archive-keyring.gpg
var ubuntuArchive []byte

// UbuntuArchiveFingerprints are the archive signing keys the embedded
// keyring must contain (checked by tests).
var UbuntuArchiveFingerprints = []string{
	"790BC7277767219C42C86F933B4FE6ACC0B21F32",
	"F6ECB3762474EDA9D21B7022871920D1991BC93C",
}

// Ubuntu returns the embedded Ubuntu archive keyring.
func Ubuntu() (openpgp.EntityList, error) {
	return parse(ubuntuArchive)
}

// Load reads a keyring file, binary (.gpg) or ASCII-armored (.asc).
func Load(path string) (openpgp.EntityList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

func parse(b []byte) (openpgp.EntityList, error) {
	var keys openpgp.EntityList
	var err error
	if bytes.Contains(b[:min(len(b), 64)], []byte("-----BEGIN PGP")) {
		keys, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(b))
	} else {
		keys, err = openpgp.ReadKeyRing(bytes.NewReader(b))
	}
	if err != nil {
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("keyring has no keys")
	}
	return keys, nil
}

// Describe returns "FINGERPRINT (first user ID)" for a key.
func Describe(e *openpgp.Entity) string {
	if e == nil || e.PrimaryKey == nil {
		return "unknown key"
	}
	fp := strings.ToUpper(fmt.Sprintf("%X", e.PrimaryKey.Fingerprint))
	for name := range e.Identities {
		return fp + " (" + name + ")"
	}
	return fp
}
