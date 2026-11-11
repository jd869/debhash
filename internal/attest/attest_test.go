package attest

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

const h1 = "2fd7c8f96a208532befb77cec1cfee8a08217a97b77d8eed382537fa6cc6e72c"
const h2 = "3e5851448bae5b36f351becde037a8b13b77307279f484eda808f8177d9a4293"

var statement = `{
 "predicate": {"attestations": [
  {"type": "https://witness.dev/attestations/command-run/v0.1",
   "attestation": {"processes": [{"openedfiles": {
     "/lib/aarch64-linux-gnu/libc.so.6": {"sha256": "` + h1 + `"},
     "/lib/aarch64-linux-gnu/../lib/libffi.so.8": {},
     "/tmp/empty": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
   }}]}},
  {"type": "https://witness.dev/attestations/product/v0.1",
   "attestation": {"/etc/os-release": {"digest": {"sha256": "` + strings.ToUpper(h2) + `"}, "mime_type": "text/plain"},
                   "relative/src.go": {"sha256": "` + h1 + `"}}}
 ]}}`

func TestParseStatementAndEnvelope(t *testing.T) {
	want := []File{{"/etc/os-release", h2}, {"/lib/aarch64-linux-gnu/libc.so.6", h1}}
	got, err := Parse([]byte(statement))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("statement: got %v", got)
	}
	env := `{"payloadType":"application/vnd.in-toto+json","payload":"` + base64.StdEncoding.EncodeToString([]byte(statement)) + `"}`
	got, err = Parse([]byte(env))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("envelope: got %v %v", got, err)
	}
}

func TestVariants(t *testing.T) {
	if got := Variants("/lib/aarch64-linux-gnu/libc.so.6"); !reflect.DeepEqual(got, []string{"/lib/aarch64-linux-gnu/libc.so.6", "/usr/lib/aarch64-linux-gnu/libc.so.6"}) {
		t.Fatal(got)
	}
	if got := Variants("/usr/bin/ls"); !reflect.DeepEqual(got, []string{"/usr/bin/ls", "/bin/ls"}) {
		t.Fatal(got)
	}
	if got := Variants("/usr/lib/gcc/aarch64-linux-gnu/13/../../../aarch64-linux-gnu/libc.so"); got[0] != "/usr/lib/aarch64-linux-gnu/libc.so" {
		t.Fatal(got)
	}
}

func TestClassify(t *testing.T) {
	for p, want := range map[string]Category{
		"/usr/lib/aarch64-linux-gnu/libssl.so.3":                CatSharedLib,
		"/usr/lib/aarch64-linux-gnu/libc.so":                    CatSharedLib,
		"/usr/bin/ls":                                           CatBinary,
		"/etc/os-release":                                       CatConfig,
		"/usr/include/python3.12/Python.h":                      CatHeader,
		"/usr/lib/python3.12/__pycache__/abc.cpython-312.pyc":   CatPyc,
		"/usr/lib/python3.12/abc.py":                            CatPython,
		"/usr/share/zoneinfo/UTC":                               CatOther,
		"/usr/local/lib/python3.12/site-packages/x.py":          CatNotSystem,
		"/home/runner/work/orjson/orjson/target/release/foo.so": CatNotSystem,
	} {
		if got := Classify(p); got != want {
			t.Errorf("Classify(%s) = %s, want %s", p, got, want)
		}
	}
}

func TestPycSource(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/lib/python3.12/__pycache__/abc.cpython-312.pyc":                "/usr/lib/python3.12/abc.py",
		"/usr/lib/python3.12/json/__pycache__/decoder.cpython-312.opt-1.pyc": "/usr/lib/python3.12/json/decoder.py",
	} {
		if got, ok := PycSource(in); !ok || got != want {
			t.Errorf("PycSource(%s) = %s %v", in, got, ok)
		}
	}
	if _, ok := PycSource("/usr/lib/python3.12/abc.py"); ok {
		t.Error("non-pyc should not map")
	}
}
