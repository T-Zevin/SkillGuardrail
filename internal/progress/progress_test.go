package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestIndicatorRendersCompletion(t *testing.T) {
	var out bytes.Buffer
	i := New(&out, true)
	i.Start(5, "starting")
	i.Set(45, "scanning")
	i.Finish("done")
	if !strings.Contains(out.String(), "100%") || !strings.Contains(out.String(), "done") {
		t.Fatalf("completion output = %q", out.String())
	}
}

func TestDisabledIndicatorIsSilent(t *testing.T) {
	var out bytes.Buffer
	i := New(&out, false)
	i.Start(5, "starting")
	i.Set(45, "scanning")
	i.Finish("done")
	if out.Len() != 0 {
		t.Fatalf("disabled output = %q", out.String())
	}
}
