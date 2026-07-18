//go:build linux

package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

var linuxPOSIXACLAttributes = []string{
	"system.posix_acl_access",
	"system.posix_acl_default",
}

func platformGuardedOperationsAvailable() error {
	return nil
}

func platformHardenTreeACL(ctx context.Context, root string) error {
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > maxDigestEntries+2 {
			return fmt.Errorf("ACL hardening entry limit exceeded (limit=%d)", maxDigestEntries+2)
		}
		return removeLinuxPOSIXACL(path)
	})
}

func platformHardenPathACL(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return removeLinuxPOSIXACL(path)
}

func platformVerifyTreeACL(ctx context.Context, root string) error {
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > maxDigestEntries+2 {
			return fmt.Errorf("ACL verification entry limit exceeded (limit=%d)", maxDigestEntries+2)
		}
		return verifyLinuxPOSIXACLAbsent(path)
	})
}

func platformVerifyACLPaths(ctx context.Context, paths ...string) error {
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := verifyLinuxPOSIXACLAbsent(path); err != nil {
			return err
		}
	}
	return nil
}

func platformVerifyBoundaryACLPaths(ctx context.Context, paths ...string) error {
	return platformVerifyACLPaths(ctx, paths...)
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

func removeLinuxPOSIXACL(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return fmt.Errorf("refusing ACL operation on non-regular path %q", path)
	}
	for _, attribute := range linuxPOSIXACLAttributes {
		err := syscall.Removexattr(path, attribute)
		if err != nil && !linuxACLAttributeAbsent(err) {
			return fmt.Errorf("remove POSIX ACL %q from %q: %w", attribute, path, err)
		}
	}
	return verifyLinuxPOSIXACLAbsent(path)
}

func verifyLinuxPOSIXACLAbsent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return fmt.Errorf("refusing ACL inspection of non-regular path %q", path)
	}
	for _, attribute := range linuxPOSIXACLAttributes {
		_, err := syscall.Getxattr(path, attribute, nil)
		if err == nil {
			return fmt.Errorf("POSIX ACL %q is present on %q", attribute, path)
		}
		if !linuxACLAttributeAbsent(err) {
			return fmt.Errorf("inspect POSIX ACL %q on %q: %w", attribute, path, err)
		}
	}
	return nil
}

func linuxACLAttributeAbsent(err error) bool {
	return errors.Is(err, syscall.ENODATA)
}
