//go:build darwin

package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const darwinACLCommandOutputLimit = 8 << 20

var darwinACLEntry = regexp.MustCompile(`(?m)^[\t ]+[0-9]+: `)
var darwinACLAllowEntry = regexp.MustCompile(`(?m)^[\t ]+[0-9]+: .*\ballow\b`)

func platformGuardedOperationsAvailable() error {
	return nil
}

func platformHardenTreeACL(ctx context.Context, root string) error {
	_, err := runDarwinACLCommand(ctx, "/bin/chmod", []string{"-RN", root})
	if err != nil {
		return fmt.Errorf("remove inherited and extended ACLs from staged skill: %w", err)
	}
	return nil
}

func platformHardenPathACL(ctx context.Context, path string) error {
	_, err := runDarwinACLCommand(ctx, "/bin/chmod", []string{"-N", path})
	if err != nil {
		return fmt.Errorf("remove extended ACL from %q: %w", path, err)
	}
	return nil
}

func platformVerifyTreeACL(ctx context.Context, root string) error {
	rootOutput, err := runDarwinACLCommand(ctx, "/bin/ls", []string{"-led", root})
	if err != nil {
		return fmt.Errorf("inspect installed skill root ACL: %w", err)
	}
	recursiveOutput, err := runDarwinACLCommand(ctx, "/bin/ls", []string{"-leAR", root})
	if err != nil {
		return fmt.Errorf("inspect installed skill descendant ACLs: %w", err)
	}
	if darwinACLEntry.Match(rootOutput) || darwinACLEntry.Match(recursiveOutput) {
		return errors.New("installed skill contains an extended ACL")
	}
	return nil
}

func platformVerifyACLPaths(ctx context.Context, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	arguments := append([]string{"-led"}, paths...)
	output, err := runDarwinACLCommand(ctx, "/bin/ls", arguments)
	if err != nil {
		return fmt.Errorf("inspect authoritative state ACLs: %w", err)
	}
	if darwinACLEntry.Match(output) {
		return errors.New("authoritative state path contains an extended ACL")
	}
	return nil
}

func platformVerifyBoundaryACLPaths(ctx context.Context, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}
	arguments := append([]string{"-led"}, paths...)
	output, err := runDarwinACLCommand(ctx, "/bin/ls", arguments)
	if err != nil {
		return fmt.Errorf("inspect directory-boundary ACLs: %w", err)
	}
	if darwinACLAllowEntry.Match(output) {
		return errors.New("directory boundary contains an ACL that grants access")
	}
	return nil
}

func platformVerifyPathOwner(path string, allowRoot bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine filesystem owner")
	}
	want := uint32(os.Geteuid())
	if stat.Uid != want && !(allowRoot && stat.Uid == 0) {
		return fmt.Errorf("path is owned by uid %d, expected uid %d", stat.Uid, want)
	}
	return nil
}

func runDarwinACLCommand(parent context.Context, executable string, arguments []string) ([]byte, error) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = darwinACLEnvironment()
	stdout := &boundedCommandBuffer{limit: darwinACLCommandOutputLimit}
	stderr := &boundedCommandBuffer{limit: 64 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("ACL inspection command exceeded its output limit")
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("ACL command timed out or was cancelled: %w", ctx.Err())
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", err, message)
	}
	return stdout.Bytes(), nil
}

func darwinACLEnvironment() []string {
	return []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
}

type boundedCommandBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedCommandBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = buffer.buffer.Write(data[:remaining])
		} else {
			_, _ = buffer.buffer.Write(data)
		}
	}
	if original > remaining {
		buffer.overflow = true
	}
	return original, nil
}

func (buffer *boundedCommandBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedCommandBuffer) String() string {
	return buffer.buffer.String()
}
