//go:build darwin

package install

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/T-Zevin/SkillGuardrail/internal/model"
	"github.com/T-Zevin/SkillGuardrail/internal/scanner"
)

func TestDarwinACLDetectionAndHardening(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "SKILL.md")
	if err := os.WriteFile(file, []byte("safe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{root, file} {
		command := exec.Command("/bin/chmod", "+a", "everyone allow write", target)
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("extended ACLs unavailable: %v (%s)", err, output)
		}
		if err := platformVerifyTreeACL(context.Background(), root); err == nil {
			t.Fatalf("extended ACL on %q was not detected", target)
		}
		if err := platformHardenTreeACL(context.Background(), root); err != nil {
			t.Fatal(err)
		}
		if err := platformVerifyTreeACL(context.Background(), root); err != nil {
			t.Fatalf("extended ACL remained after hardening: %v", err)
		}
	}
}

func TestInstallRejectsACLWritableStagingParent(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "skills")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	acl := "everyone allow list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit"
	command := exec.Command("/bin/chmod", "+a", acl, parent)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("inheritable ACLs unavailable: %v (%s)", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-RN", parent).Run() })

	root := filepath.Join("..", "..", "testdata", "safe-skill")
	report, err := scanner.Scan(context.Background(), root, model.SourceInfo{Input: root, Kind: "local", Resolved: root}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Install(context.Background(), root, report, Options{
		Directory: target, AllowedRisk: model.SeverityMedium, ToolVersion: "test", StateDir: privateTempDir(t),
	})
	if err == nil || !strings.Contains(err.Error(), "ACL") {
		t.Fatalf("unsafe staging parent was not rejected: %v", err)
	}
}
