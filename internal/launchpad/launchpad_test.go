package launchpad

import (
	"context"
	"testing"
	"time"

	"github.com/jd869/debhash/internal/launchpad/lptest"
)

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestWindow(t *testing.T) {
	lp := lptest.New(t)
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.0", Pocket: "Release", Published: "2024-04-20T10:00:00+00:00", Superseded: "2025-10-01T10:00:00+00:00", SHA256: "aa"})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.1", Pocket: "Updates", Published: "2025-10-01T10:00:00+00:00", Superseded: "2025-12-20T10:00:00+00:00", SHA256: "bb"})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.1", Pocket: "Security", Published: "2025-10-01T11:00:00+00:00", SHA256: "bb"})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.2", Pocket: "Updates", Published: "2025-12-20T10:00:00+00:00", SHA256: "cc"})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "1.3~rc", Pocket: "Proposed", Published: "2025-11-01T10:00:00+00:00", SHA256: "dd"})
	lp.Add(lptest.Pub{Name: "libfoo1", Version: "0.9", Pocket: "Updates", Published: "2023-01-01T10:00:00+00:00", Superseded: "2024-01-01T10:00:00+00:00", SHA256: "ee"})
	lp.Add(lptest.Pub{Name: "libfoo-doc", Version: "1.1", Pocket: "Updates", Published: "2025-10-01T10:00:00+00:00", SHA256: "ff", ArchIndep: true})

	c := &Client{API: lp.URL()}
	got, err := c.Window(context.Background(), "ubuntu", "noble", "arm64", "libfoo1", day("2025-09-01"), day("2025-12-10"))
	if err != nil {
		t.Fatal(err)
	}
	// 1.0 (superseded inside the window), 1.1 in two pockets; not 1.2 (too
	// new), 0.9 (too old), 1.3~rc (Proposed), libfoo-doc (other name).
	var seen []string
	for _, b := range got {
		seen = append(seen, b.Version+"/"+b.Pocket+"/"+b.SHA256)
	}
	want := []string{"1.0/Release/aa", "1.1/Security/bb", "1.1/Updates/bb"}
	if len(seen) != len(want) {
		t.Fatalf("got %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("got %v, want %v", seen, want)
		}
	}
	if got[0].URL == "" || got[0].Arch != "arm64" || got[0].Source != "libfoo1-src" {
		t.Fatalf("binary = %+v", got[0])
	}
	// One binaryFileUrls call per version, not per pocket.
	if n := lp.FileCalls(); n != 2 {
		t.Fatalf("binaryFileUrls calls = %d, want 2", n)
	}

	doc, err := c.Window(context.Background(), "ubuntu", "noble", "arm64", "libfoo-doc", day("2025-09-01"), day("2025-12-10"))
	if err != nil || len(doc) != 1 || doc[0].Arch != "all" {
		t.Fatalf("arch-independent = %+v %v", doc, err)
	}
}

func TestSuite(t *testing.T) {
	if Suite("noble", "Release") != "noble" || Suite("noble", "Updates") != "noble-updates" || Suite("noble", "Security") != "noble-security" {
		t.Fatal("Suite mapping")
	}
}
