//go:build linux

package install

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLinuxACLDetectionAndHardening(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "SKILL.md")
	if err := os.WriteFile(file, []byte("safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	acl := linuxTestACL()
	for path, attribute := range map[string]string{
		file: "system.posix_acl_access",
		root: "system.posix_acl_default",
	} {
		if err := syscall.Setxattr(path, attribute, acl, 0); err != nil {
			if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPERM) {
				t.Skipf("POSIX ACL test fixture unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	if err := platformVerifyTreeACL(context.Background(), root); err == nil {
		t.Fatal("POSIX ACL was not detected")
	}
	if err := platformHardenTreeACL(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if err := platformVerifyTreeACL(context.Background(), root); err != nil {
		t.Fatalf("POSIX ACL remained after hardening: %v", err)
	}
}

func TestLinuxACLAbsentClassificationFailsClosed(t *testing.T) {
	if !linuxACLAttributeAbsent(syscall.ENODATA) {
		t.Fatal("ENODATA should mean the requested ACL xattr is absent")
	}
	if linuxACLAttributeAbsent(syscall.ENOTSUP) || linuxACLAttributeAbsent(syscall.EOPNOTSUPP) {
		t.Fatal("an unsupported ACL query must not be treated as proof of absence")
	}
}

func linuxTestACL() []byte {
	const undefinedID = ^uint32(0)
	entries := []struct {
		tag  uint16
		perm uint16
		id   uint32
	}{
		{tag: 0x01, perm: 0x07, id: undefinedID},
		{tag: 0x02, perm: 0x04, id: 65534},
		{tag: 0x04, perm: 0x00, id: undefinedID},
		{tag: 0x10, perm: 0x04, id: undefinedID},
		{tag: 0x20, perm: 0x00, id: undefinedID},
	}
	data := make([]byte, 4+len(entries)*8)
	binary.LittleEndian.PutUint32(data[0:4], 0x0002)
	for index, entry := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(data[offset:offset+2], entry.tag)
		binary.LittleEndian.PutUint16(data[offset+2:offset+4], entry.perm)
		binary.LittleEndian.PutUint32(data[offset+4:offset+8], entry.id)
	}
	return data
}
