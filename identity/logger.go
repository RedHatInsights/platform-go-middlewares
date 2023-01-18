package identity

import "context"

// ErrorFunc is a callback logging function for decoding, parsing and validation errors.
type ErrorFunc func(ctx context.Context, rawIdentity, message string)

func noopErrorFunc(_ context.Context, _, _ string) {
	// do nothing
}
