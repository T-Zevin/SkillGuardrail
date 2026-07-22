package source

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
)

const (
	defaultMaxArchiveBytes      = 64 << 20
	defaultMaxExtractBytes      = 128 << 20
	defaultMaxUncompressedBytes = 160 << 20
	defaultMaxExtractFiles      = 10000
	hardMaxArchiveBytes         = 512 << 20
	hardMaxExtractBytes         = 1 << 30
	hardMaxUncompressedBytes    = 1 << 30
	hardMaxExtractFiles         = 100000
	maxExtractDepth             = 32
	maxCompressionRatio         = 100
)

var (
	githubPart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	commitSHA  = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

	reservedAddressPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fec0::/10"),
	}
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)
type lookupIPFunc func(context.Context, string) ([]net.IPAddr, error)

type Resolved struct {
	Root   string
	Source model.SourceInfo

	cleanupOnce sync.Once
	cleanupFn   func() error
}

// Limits bounds the untrusted source acquisition and extraction phase. The
// defaults are deliberately finite, while callers may raise them within the
// hard ceilings for large but trusted repositories.
type Limits struct {
	MaxArchiveBytes      int64
	MaxExtractBytes      int64
	MaxUncompressedBytes int64
	MaxExtractFiles      int
}

func DefaultLimits() Limits {
	return Limits{
		MaxArchiveBytes:      defaultMaxArchiveBytes,
		MaxExtractBytes:      defaultMaxExtractBytes,
		MaxUncompressedBytes: defaultMaxUncompressedBytes,
		MaxExtractFiles:      defaultMaxExtractFiles,
	}
}

func (l Limits) normalize() (Limits, error) {
	defaults := DefaultLimits()
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = defaults.MaxArchiveBytes
	}
	if l.MaxExtractBytes <= 0 {
		l.MaxExtractBytes = defaults.MaxExtractBytes
	}
	if l.MaxUncompressedBytes <= 0 {
		l.MaxUncompressedBytes = defaults.MaxUncompressedBytes
	}
	if l.MaxExtractFiles <= 0 {
		l.MaxExtractFiles = defaults.MaxExtractFiles
	}
	switch {
	case l.MaxArchiveBytes > hardMaxArchiveBytes:
		return Limits{}, fmt.Errorf("maximum archive size may not exceed %s", formatLimit(hardMaxArchiveBytes))
	case l.MaxExtractBytes > hardMaxExtractBytes:
		return Limits{}, fmt.Errorf("maximum extracted size may not exceed %s", formatLimit(hardMaxExtractBytes))
	case l.MaxUncompressedBytes > hardMaxUncompressedBytes:
		return Limits{}, fmt.Errorf("maximum uncompressed size may not exceed %s", formatLimit(hardMaxUncompressedBytes))
	case l.MaxExtractFiles > hardMaxExtractFiles:
		return Limits{}, fmt.Errorf("maximum source entries may not exceed %d", hardMaxExtractFiles)
	case l.MaxExtractBytes > l.MaxUncompressedBytes:
		return Limits{}, errors.New("maximum extracted size may not exceed maximum uncompressed size")
	}
	return l, nil
}

func (r *Resolved) Cleanup() error {
	var err error
	r.cleanupOnce.Do(func() {
		if r.cleanupFn != nil {
			err = r.cleanupFn()
		}
	})
	return err
}

func Resolve(ctx context.Context, input string) (*Resolved, error) {
	return ResolveWithLimits(ctx, input, DefaultLimits())
}

func ResolveWithLimits(ctx context.Context, input string, limits Limits) (*Resolved, error) {
	normalized, err := limits.normalize()
	if err != nil {
		return nil, err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.New("source is required")
	}
	if strings.Contains(input, "://") {
		return resolveGitHub(ctx, input, normalized)
	}
	return resolveLocal(ctx, input, normalized)
}

func resolveLocal(ctx context.Context, input string, limits Limits) (*Resolved, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, fmt.Errorf("resolve local source: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("open local source: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("the source root may not be a symbolic link")
	}
	root := abs
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, errors.New("a local source must be a regular SKILL.md file or directory")
		}
		if !strings.EqualFold(filepath.Base(abs), "SKILL.md") {
			return nil, errors.New("a local source must be a skill directory or SKILL.md")
		}
		root = filepath.Dir(abs)
	}
	quarantine, err := os.MkdirTemp("", "skillguardrail-quarantine-")
	if err != nil {
		return nil, fmt.Errorf("create local quarantine: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(quarantine) }
	if err := os.Chmod(quarantine, 0o700); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("secure local quarantine: %w", err)
	}
	snapshot := filepath.Join(quarantine, "repository")
	if err := copyLocalSnapshot(ctx, root, snapshot, limits); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("snapshot local source into quarantine: %w", err)
	}
	return &Resolved{
		Root: snapshot,
		Source: model.SourceInfo{
			Input: input, Kind: "local", Resolved: root,
		},
		cleanupFn: cleanup,
	}, nil
}

func copyLocalSnapshot(ctx context.Context, sourceRoot, destinationRoot string, limits Limits) error {
	seen := map[string]string{}
	entries := 0
	var total int64
	return filepath.WalkDir(sourceRoot, func(sourcePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceRoot, sourcePath)
		if err != nil {
			return err
		}
		if rel == "." {
			if err := os.Mkdir(destinationRoot, 0o700); err != nil {
				return err
			}
			return os.Chmod(destinationRoot, 0o700)
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == ".venv") {
			return filepath.SkipDir
		}
		if entry.Name() == ".skillguardrail.lock" {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if strings.ContainsRune(relSlash, '\x00') || strings.Contains(relSlash, "\\") {
			return fmt.Errorf("unsafe local path %q", relSlash)
		}
		if len(strings.Split(relSlash, "/")) > maxExtractDepth {
			return fmt.Errorf("local path exceeds maximum depth: %q", relSlash)
		}
		folded := strings.ToLower(relSlash)
		if previous, ok := seen[folded]; ok && previous != relSlash {
			return fmt.Errorf("case-folding path collision between %q and %q", previous, relSlash)
		}
		seen[folded] = relSlash
		entries++
		if entries > limits.MaxExtractFiles {
			return fmt.Errorf("local source exceeds %d entries", limits.MaxExtractFiles)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("refusing non-regular local entry %q", relSlash)
		}
		target := filepath.Join(destinationRoot, rel)
		if info.IsDir() {
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			return os.Chmod(target, 0o700)
		}
		if info.Size() < 0 || info.Size() > limits.MaxExtractBytes || total+info.Size() > limits.MaxExtractBytes {
			return fmt.Errorf("local source exceeds %s", formatLimit(limits.MaxExtractBytes))
		}
		input, err := os.Open(sourcePath)
		if err != nil {
			return err
		}
		openedInfo, err := input.Stat()
		if err != nil {
			_ = input.Close()
			return err
		}
		if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			_ = input.Close()
			return fmt.Errorf("local entry changed while opening %q", relSlash)
		}
		mode := os.FileMode(0o600)
		if info.Mode()&0o111 != 0 {
			mode = 0o700
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			_ = input.Close()
			return err
		}
		written, copyErr := io.CopyN(output, input, info.Size())
		inputErr := input.Close()
		outputErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if inputErr != nil {
			return inputErr
		}
		if outputErr != nil {
			return outputErr
		}
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
		total += written
		return nil
	})
}

func ParseGitHubURL(raw string) (string, string, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", "", fmt.Errorf("parse URL: %w", err)
	}
	if u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") {
		return "", "", "", errors.New("remote sources must use https://github.com/OWNER/REPO")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return "", "", "", errors.New("GitHub source URL may not contain credentials, a port, query, or fragment")
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) != 2 {
		return "", "", "", errors.New("GitHub source must point to a repository root")
	}
	owner, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", errors.New("invalid GitHub owner")
	}
	repo, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", "", errors.New("invalid GitHub repository")
	}
	repo = strings.TrimSuffix(repo, ".git")
	if !githubPart.MatchString(owner) || !githubPart.MatchString(repo) || owner == "." || repo == "." {
		return "", "", "", errors.New("invalid GitHub owner or repository name")
	}
	canonical := "https://github.com/" + owner + "/" + repo
	return owner, repo, canonical, nil
}

func resolveGitHub(ctx context.Context, raw string, limits Limits) (*Resolved, error) {
	owner, repo, canonical, err := ParseGitHubURL(raw)
	if err != nil {
		return nil, err
	}
	client := newGitHubClient()
	sha, err := resolveCommit(ctx, client, owner, repo)
	if err != nil {
		return nil, err
	}

	quarantine, err := os.MkdirTemp("", "skillguardrail-quarantine-")
	if err != nil {
		return nil, fmt.Errorf("create quarantine: %w", err)
	}
	if err := os.Chmod(quarantine, 0o700); err != nil {
		_ = os.RemoveAll(quarantine)
		return nil, fmt.Errorf("secure quarantine permissions: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(quarantine) }
	root := filepath.Join(quarantine, "repository")
	if err := os.Mkdir(root, 0o700); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("create quarantine root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("secure quarantine root: %w", err)
	}

	archiveURL := "https://codeload.github.com/" + owner + "/" + repo + "/tar.gz/" + sha
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("create archive request: %w", err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "SkillGuardrail")
	resp, err := client.Do(req)
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("download immutable GitHub archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = cleanup()
		return nil, fmt.Errorf("download immutable GitHub archive: HTTP %s", resp.Status)
	}
	if resp.ContentLength > limits.MaxArchiveBytes {
		_ = cleanup()
		return nil, fmt.Errorf("GitHub archive is larger than %s", formatLimit(limits.MaxArchiveBytes))
	}

	archiveFile, err := os.CreateTemp(quarantine, "archive-*.tar.gz")
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("create archive quarantine file: %w", err)
	}
	archivePath := archiveFile.Name()
	if err := archiveFile.Chmod(0o600); err != nil {
		_ = archiveFile.Close()
		_ = cleanup()
		return nil, fmt.Errorf("secure archive quarantine file: %w", err)
	}
	archiveBytes, archiveHash, err := storeArchive(resp.Body, archiveFile, limits.MaxArchiveBytes)
	closeErr := archiveFile.Close()
	if err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("download immutable GitHub archive: %w", err)
	}
	if closeErr != nil {
		_ = cleanup()
		return nil, fmt.Errorf("close downloaded GitHub archive: %w", closeErr)
	}
	expectedArchiveRoot := repo + "-" + sha
	if err := extractDownloadedArchive(ctx, archivePath, root, expectedArchiveRoot, archiveBytes, limits); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("safely extract GitHub archive: %w", err)
	}
	if err := os.Remove(archivePath); err != nil {
		_ = cleanup()
		return nil, fmt.Errorf("remove downloaded GitHub archive: %w", err)
	}

	return &Resolved{
		Root: root,
		Source: model.SourceInfo{
			Input: raw, Kind: "github", Resolved: canonical + "/commit/" + sha,
			Repository: owner + "/" + repo, Commit: sha,
			ArchiveSHA256: archiveHash,
		},
		cleanupFn: cleanup,
	}, nil
}

func newGitHubClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 20 * time.Second
	baseDial := transport.DialContext
	if baseDial == nil {
		baseDial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	lookup := net.DefaultResolver.LookupIPAddr
	transport.DialContext = guardedGitHubDialContext(baseDial, lookup)
	baseProxy := transport.Proxy
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		if baseProxy == nil {
			return nil, nil
		}
		proxyURL, err := baseProxy(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err
		}
		if isAllowedGitHubHost(req.URL.Hostname()) {
			if _, err := resolvePublicIPs(req.Context(), req.URL.Hostname(), lookup); err != nil {
				return nil, err
			}
		}
		return proxyURL, nil
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if err := validateGitHubRedirectURL(req.URL); err != nil {
				return err
			}
			if len(via) > 0 && !strings.EqualFold(via[len(via)-1].URL.Hostname(), req.URL.Hostname()) {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}

func validateGitHubRedirectURL(value *url.URL) error {
	if value == nil || !strings.EqualFold(value.Scheme, "https") {
		return errors.New("refusing non-HTTPS GitHub redirect")
	}
	if value.User != nil {
		return errors.New("refusing GitHub redirect containing user information")
	}
	if value.Port() != "" {
		return errors.New("refusing GitHub redirect containing a port")
	}
	host := value.Hostname()
	if !isAllowedGitHubHost(host) {
		return fmt.Errorf("refusing redirect to untrusted host %q", strings.ToLower(host))
	}
	return nil
}

func isAllowedGitHubHost(host string) bool {
	switch strings.ToLower(host) {
	case "github.com", "api.github.com", "codeload.github.com":
		return true
	default:
		return false
	}
}

func guardedGitHubDialContext(baseDial dialContextFunc, lookup lookupIPFunc) dialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("parse network address %q: %w", address, err)
		}
		if !isAllowedGitHubHost(host) {
			// A non-GitHub address here is an explicitly configured HTTP proxy.
			return baseDial(ctx, network, address)
		}
		if port != "443" {
			return nil, fmt.Errorf("refusing GitHub connection on port %q", port)
		}
		addresses, err := resolvePublicIPs(ctx, host, lookup)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, candidate := range addresses {
			connection, err := baseDial(ctx, network, net.JoinHostPort(candidate.String(), port))
			if err == nil {
				// net/http performs TLS after DialContext using the original request
				// hostname, so certificate verification remains bound to GitHub.
				return connection, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, fmt.Errorf("connect to public GitHub address: %w", lastErr)
		}
		return nil, fmt.Errorf("GitHub host %q did not resolve to a public address", host)
	}
}

func resolvePublicIPs(ctx context.Context, host string, lookup lookupIPFunc) ([]netip.Addr, error) {
	resolved, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve GitHub host %q: %w", host, err)
	}
	public := make([]netip.Addr, 0, len(resolved))
	for _, candidate := range resolved {
		address, ok := netip.AddrFromSlice(candidate.IP)
		if !ok {
			continue
		}
		address = address.Unmap()
		if isPublicAddress(address) {
			public = append(public, address)
		}
	}
	if len(public) == 0 {
		return nil, fmt.Errorf("refusing non-public DNS result for GitHub host %q", host)
	}
	return public, nil
}

func isPublicAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedAddressPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func storeArchive(reader io.Reader, destination io.Writer, maxBytes ...int64) (int64, string, error) {
	limit := DefaultLimits().MaxArchiveBytes
	if len(maxBytes) > 0 && maxBytes[0] > 0 {
		limit = maxBytes[0]
	}
	limited := &io.LimitedReader{R: reader, N: limit + 1}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(destination, hasher), limited)
	if err != nil {
		return written, "", err
	}
	if written > limit {
		return written, "", fmt.Errorf("GitHub archive exceeds %s", formatLimit(limit))
	}
	return written, hex.EncodeToString(hasher.Sum(nil)), nil
}

func extractDownloadedArchive(ctx context.Context, archivePath, root, expectedRoot string, compressedBytes int64, configuredLimits ...Limits) error {
	limits := DefaultLimits()
	if len(configuredLimits) > 0 {
		limits = configuredLimits[0]
	}
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open downloaded archive: %w", err)
	}
	defer archiveFile.Close()

	buffered := bufio.NewReader(archiveFile)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	gzipReader.Multistream(false)

	limited := &io.LimitedReader{R: &contextReader{ctx: ctx, reader: gzipReader}, N: limits.MaxUncompressedBytes + 1}
	uncompressed := &countingReader{reader: limited}
	if _, err := extractTar(ctx, tar.NewReader(uncompressed), root, expectedRoot, limits); err != nil {
		_ = gzipReader.Close()
		return err
	}
	if _, err := io.Copy(zeroWriter{}, uncompressed); err != nil {
		_ = gzipReader.Close()
		return fmt.Errorf("invalid data after tar end marker: %w", err)
	}
	if uncompressed.count > limits.MaxUncompressedBytes {
		_ = gzipReader.Close()
		return fmt.Errorf("archive exceeds %s uncompressed bytes", formatLimit(limits.MaxUncompressedBytes))
	}
	if err := gzipReader.Close(); err != nil {
		return fmt.Errorf("close gzip stream: %w", err)
	}
	if compressedBytes > 0 && uncompressed.count > 1<<20 && uncompressed.count > compressedBytes*maxCompressionRatio {
		return fmt.Errorf("GitHub archive exceeds maximum compression ratio %d:1", maxCompressionRatio)
	}
	if _, err := buffered.ReadByte(); err == nil {
		return errors.New("compressed data follows the first gzip stream")
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("check for trailing compressed data: %w", err)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

type zeroWriter struct{}

func (zeroWriter) Write(buffer []byte) (int, error) {
	for _, value := range buffer {
		if value != 0 {
			return 0, errors.New("non-zero trailing tar data")
		}
	}
	return len(buffer), nil
}

func resolveCommit(ctx context.Context, client *http.Client, owner, repo string) (string, error) {
	endpoint := "https://api.github.com/repos/" + owner + "/" + repo + "/commits/HEAD"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create GitHub API request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "SkillGuardrail")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resolve immutable GitHub commit: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve immutable GitHub commit: HTTP %s", resp.Status)
	}
	var result struct {
		SHA string `json:"sha"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&result); err != nil {
		return "", fmt.Errorf("decode GitHub commit response: %w", err)
	}
	if !commitSHA.MatchString(result.SHA) {
		return "", errors.New("GitHub returned an invalid commit SHA")
	}
	return strings.ToLower(result.SHA), nil
}

type countingReader struct {
	reader io.Reader
	count  int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.count += int64(n)
	return n, err
}

func extractTar(ctx context.Context, reader *tar.Reader, root, expectedRoot string, configuredLimits ...Limits) (int64, error) {
	limits := DefaultLimits()
	if len(configuredLimits) > 0 {
		limits = configuredLimits[0]
	}
	seen := map[string]string{}
	archiveRoot := ""
	var total int64
	files := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return total, err
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			if archiveRoot != "" {
				return total, errors.New("global tar header appears after repository entries")
			}
			continue
		}
		if strings.ContainsRune(header.Name, '\x00') || strings.Contains(header.Name, "\\") {
			return total, fmt.Errorf("unsafe archive path %q", header.Name)
		}
		clean := path.Clean(header.Name)
		if clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return total, fmt.Errorf("unsafe archive path %q", header.Name)
		}
		parts := strings.Split(clean, "/")
		entryRoot := parts[0]
		if archiveRoot == "" {
			if !strings.EqualFold(entryRoot, expectedRoot) {
				return total, fmt.Errorf("unexpected archive root %q (want %q)", entryRoot, expectedRoot)
			}
			archiveRoot = entryRoot
		} else if entryRoot != archiveRoot {
			return total, fmt.Errorf("archive contains multiple roots %q and %q", archiveRoot, entryRoot)
		}
		if len(parts) < 2 {
			if header.Typeflag != tar.TypeDir {
				return total, fmt.Errorf("refusing non-directory archive root %q", entryRoot)
			}
			continue
		}
		rel := path.Join(parts[1:]...)
		if rel == "." {
			continue
		}
		if len(strings.Split(rel, "/")) > maxExtractDepth {
			return total, fmt.Errorf("archive path exceeds maximum depth: %q", rel)
		}
		folded := strings.ToLower(rel)
		if previous, ok := seen[folded]; ok && previous != rel {
			return total, fmt.Errorf("case-folding path collision between %q and %q", previous, rel)
		}
		seen[folded] = rel
		files++
		if files > limits.MaxExtractFiles {
			return total, fmt.Errorf("archive exceeds %d entries", limits.MaxExtractFiles)
		}

		target := filepath.Join(root, filepath.FromSlash(rel))
		relCheck, err := filepath.Rel(root, target)
		if err != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
			return total, fmt.Errorf("archive entry escapes quarantine: %q", rel)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return total, err
			}
			if err := os.Chmod(target, 0o700); err != nil {
				return total, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > limits.MaxExtractBytes || total+header.Size > limits.MaxExtractBytes {
				return total, fmt.Errorf("archive exceeds %s extracted bytes", formatLimit(limits.MaxExtractBytes))
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return total, err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return total, fmt.Errorf("create extracted file %q: %w", rel, err)
			}
			written, copyErr := io.CopyN(file, reader, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return total, fmt.Errorf("extract file %q: %w", rel, copyErr)
			}
			if closeErr != nil {
				return total, closeErr
			}
			if err := os.Chmod(target, 0o600); err != nil {
				return total, err
			}
			total += written
		default:
			return total, fmt.Errorf("refusing non-regular archive entry %q (type %d)", rel, header.Typeflag)
		}
	}
	if archiveRoot == "" {
		return total, errors.New("archive does not contain the expected repository root")
	}
	return total, nil
}

func formatLimit(value int64) string {
	if value > 0 && value%(1<<20) == 0 {
		return fmt.Sprintf("%d MiB (%d bytes)", value>>20, value)
	}
	return fmt.Sprintf("%d bytes", value)
}
