package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseGitHubURL(t *testing.T) {
	owner, repo, canonical, err := ParseGitHubURL("https://github.com/T-Zevin/SkillGuardrail.git")
	if err != nil {
		t.Fatal(err)
	}
	if owner != "T-Zevin" || repo != "SkillGuardrail" {
		t.Fatalf("unexpected repository: %s/%s", owner, repo)
	}
	if canonical != "https://github.com/T-Zevin/SkillGuardrail" {
		t.Fatalf("unexpected canonical URL: %s", canonical)
	}
}

func TestExtractTarRejectsTraversalAndLinks(t *testing.T) {
	for name, entry := range map[string]tar.Header{
		"traversal": {Name: "root/../../outside", Typeflag: tar.TypeReg, Size: 0},
		"symlink":   {Name: "root/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	} {
		t.Run(name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			if err := writer.WriteHeader(&entry); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := extractTar(context.Background(), tar.NewReader(bytes.NewReader(archive.Bytes())), t.TempDir(), "root"); err == nil {
				t.Fatal("expected unsafe archive to be rejected")
			}
		})
	}
}

func TestExtractTarWritesRegularFiles(t *testing.T) {
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	content := []byte("safe\n")
	if err := writer.WriteHeader(&tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "repo-SHA/SKILL.md", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if _, err := extractTar(context.Background(), tar.NewReader(bytes.NewReader(archive.Bytes())), root, "REPO-sha"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content = %q", got)
	}
}

func TestRedirectPolicy(t *testing.T) {
	client := newGitHubClient()
	previous, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/o/r", nil)
	next, _ := http.NewRequest(http.MethodGet, "https://codeload.github.com/o/r/tar.gz/sha", nil)
	next.Header.Set("Authorization", "Bearer must-not-cross-hosts")
	if err := client.CheckRedirect(next, []*http.Request{previous}); err != nil {
		t.Fatal(err)
	}
	if next.Header.Get("Authorization") != "" {
		t.Fatal("authorization survived a cross-host redirect")
	}
	for _, raw := range []string{
		"https://example.invalid/archive",
		"http://codeload.github.com/o/r/tar.gz/sha",
		"https://user@codeload.github.com/o/r/tar.gz/sha",
		"https://codeload.github.com:443/o/r/tar.gz/sha",
	} {
		redirect, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckRedirect(redirect, []*http.Request{previous}); err == nil {
			t.Errorf("expected redirect %q to be rejected", raw)
		}
	}
}

func TestPublicAddressPolicy(t *testing.T) {
	for _, test := range []struct {
		address string
		public  bool
	}{
		{address: "8.8.8.8", public: true},
		{address: "2606:4700:4700::1111", public: true},
		{address: "127.0.0.1"},
		{address: "10.0.0.1"},
		{address: "100.64.0.1"},
		{address: "169.254.1.1"},
		{address: "192.0.2.1"},
		{address: "198.18.0.1"},
		{address: "224.0.0.1"},
		{address: "240.0.0.1"},
		{address: "::1"},
		{address: "fc00::1"},
		{address: "fe80::1"},
		{address: "ff02::1"},
		{address: "2001:db8::1"},
		{address: "64:ff9b::c000:201"},
	} {
		t.Run(test.address, func(t *testing.T) {
			if got := isPublicAddress(netip.MustParseAddr(test.address)); got != test.public {
				t.Fatalf("isPublicAddress(%s) = %t, want %t", test.address, got, test.public)
			}
		})
	}
}

func TestGuardedGitHubDialUsesOnlyValidatedAddresses(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("127.0.0.1")},
			{IP: net.ParseIP("8.8.8.8")},
			{IP: net.ParseIP("169.254.169.254")},
		}, nil
	}
	var dialed []string
	dial := func(_ context.Context, _, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		return nil, errors.New("test dial stopped")
	}
	_, err := guardedGitHubDialContext(dial, lookup)(context.Background(), "tcp", "api.github.com:443")
	if err == nil {
		t.Fatal("expected the test dial to fail")
	}
	if len(dialed) != 1 || dialed[0] != "8.8.8.8:443" {
		t.Fatalf("dialed addresses = %#v, want only the validated public address", dialed)
	}
}

func TestGuardedGitHubDialRejectsPrivateOnlyDNS(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("10.0.0.1")}}, nil
	}
	dialCalled := false
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("must not dial")
	}
	if _, err := guardedGitHubDialContext(dial, lookup)(context.Background(), "tcp", "codeload.github.com:443"); err == nil {
		t.Fatal("expected private-only DNS response to be rejected")
	}
	if dialCalled {
		t.Fatal("dial was attempted for a non-public DNS result")
	}
}

func TestExtractTarRequiresOneExpectedRoot(t *testing.T) {
	for _, test := range []struct {
		name     string
		entries  []tar.Header
		expected string
	}{
		{
			name:     "unexpected root",
			entries:  []tar.Header{{Name: "other/SKILL.md", Typeflag: tar.TypeReg}},
			expected: "repo-sha",
		},
		{
			name: "multiple roots",
			entries: []tar.Header{
				{Name: "repo-sha/SKILL.md", Typeflag: tar.TypeReg},
				{Name: "REPO-SHA/other.txt", Typeflag: tar.TypeReg},
			},
			expected: "repo-sha",
		},
		{
			name:     "root is not a directory",
			entries:  []tar.Header{{Name: "repo-sha", Typeflag: tar.TypeReg}},
			expected: "repo-sha",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := tar.NewWriter(&archive)
			for i := range test.entries {
				if err := writer.WriteHeader(&test.entries[i]); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := extractTar(context.Background(), tar.NewReader(bytes.NewReader(archive.Bytes())), t.TempDir(), test.expected); err == nil {
				t.Fatal("expected archive root validation to fail")
			}
		})
	}
}

func TestStoreArchiveHashesCompleteBody(t *testing.T) {
	payload := append(gzipTar(t, "repo-sha", []byte("safe\n")), []byte("trailing-body")...)
	var destination bytes.Buffer
	written, got, err := storeArchive(bytes.NewReader(payload), &destination)
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len(payload)) || !bytes.Equal(destination.Bytes(), payload) {
		t.Fatal("archive body was not stored completely")
	}
	want := sha256.Sum256(payload)
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("archive hash = %q, want %q", got, hex.EncodeToString(want[:]))
	}
}

func TestSourceLimitsHaveBoundedDefaultsAndOverrides(t *testing.T) {
	defaults, err := (Limits{}).normalize()
	if err != nil {
		t.Fatal(err)
	}
	if defaults.MaxArchiveBytes != 64<<20 || defaults.MaxExtractBytes != 128<<20 || defaults.MaxUncompressedBytes != 160<<20 || defaults.MaxExtractFiles != 10000 {
		t.Fatalf("defaults = %#v", defaults)
	}
	if _, err := (Limits{MaxArchiveBytes: hardMaxArchiveBytes + 1}).normalize(); err == nil {
		t.Fatal("oversized archive limit was accepted")
	}
	if _, err := (Limits{MaxExtractBytes: 200, MaxUncompressedBytes: 100}).normalize(); err == nil {
		t.Fatal("extract limit above uncompressed limit was accepted")
	}
}

func TestStoreArchiveHonorsConfiguredLimit(t *testing.T) {
	var destination bytes.Buffer
	if _, _, err := storeArchive(bytes.NewReader([]byte("12345")), &destination, 4); err == nil {
		t.Fatal("oversized archive was accepted")
	}
}

func TestExtractDownloadedArchiveValidatesGzipAndTrailingData(t *testing.T) {
	valid := gzipTar(t, "repo-sha", []byte("safe\n"))
	corruptChecksum := append([]byte(nil), valid...)
	corruptChecksum[len(corruptChecksum)-8] ^= 0xff

	tarWithTail := tarBytes(t, "repo-sha", []byte("safe\n"))
	tarWithTail = append(tarWithTail, []byte("hidden-after-tar")...)
	compressedTarTail := gzipBytes(t, tarWithTail)

	for _, test := range []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "valid", data: valid},
		{name: "bad checksum", data: corruptChecksum, wantErr: true},
		{name: "compressed trailing bytes", data: append(append([]byte(nil), valid...), []byte("trailer")...), wantErr: true},
		{name: "data after tar end marker", data: compressedTarTail, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
			if err := os.WriteFile(archivePath, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			err := extractDownloadedArchive(context.Background(), archivePath, t.TempDir(), "repo-sha", int64(len(test.data)))
			if test.wantErr && err == nil {
				t.Fatal("expected archive validation to fail")
			}
			if !test.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func gzipTar(t *testing.T, root string, content []byte) []byte {
	t.Helper()
	return gzipBytes(t, tarBytes(t, root, content))
}

func tarBytes(t *testing.T, root string, content []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	if err := writer.WriteHeader(&tar.Header{Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: root + "/SKILL.md", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return archive.Bytes()
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestParseGitHubURLRejectsUnsafeForms(t *testing.T) {
	for _, value := range []string{
		"http://github.com/owner/repo",
		"https://example.com/owner/repo",
		"https://token@github.com/owner/repo",
		"https://github.com/owner/repo/tree/main",
		"https://github.com/owner/repo?ref=main",
	} {
		if _, _, _, err := ParseGitHubURL(value); err == nil {
			t.Errorf("expected %q to be rejected", value)
		}
	}
}

func TestResolveLocalDirectoryAndSkillFile(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(skill, []byte("# test"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{dir, skill} {
		resolved, err := Resolve(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Root == dir {
			t.Fatalf("local source was not copied into quarantine: %q", resolved.Root)
		}
		if resolved.Source.Kind != "local" {
			t.Fatalf("kind = %q", resolved.Source.Kind)
		}
		if resolved.Source.Resolved != dir {
			t.Fatalf("resolved provenance = %q, want %q", resolved.Source.Resolved, dir)
		}
		if _, err := os.Stat(filepath.Join(resolved.Root, "SKILL.md")); err != nil {
			t.Fatalf("quarantined SKILL.md: %v", err)
		}
		if err := resolved.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestResolveRejectsSymlinkRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Resolve(context.Background(), link); err == nil {
		t.Fatal("expected symlink source to be rejected")
	}
}

func TestResolveRejectsNestedSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("SKILL.md", filepath.Join(dir, "alias.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Resolve(context.Background(), dir); err == nil {
		t.Fatal("expected nested symlink to be rejected")
	}
}
