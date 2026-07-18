//go:build !darwin && !linux

package install

import (
	"context"
	"errors"
)

var errGuardedOperationsUnsupported = errors.New("guarded install and verify are disabled on this platform because filesystem ACLs cannot be verified safely; scan remains available")

func platformGuardedOperationsAvailable() error {
	return errGuardedOperationsUnsupported
}

func platformHardenTreeACL(context.Context, string) error {
	return errGuardedOperationsUnsupported
}

func platformHardenPathACL(context.Context, string) error {
	return errGuardedOperationsUnsupported
}

func platformVerifyTreeACL(context.Context, string) error {
	return errGuardedOperationsUnsupported
}

func platformVerifyACLPaths(context.Context, ...string) error {
	return errGuardedOperationsUnsupported
}

func platformVerifyBoundaryACLPaths(context.Context, ...string) error {
	return errGuardedOperationsUnsupported
}

func platformVerifyPathOwner(string, bool) error {
	return errGuardedOperationsUnsupported
}
