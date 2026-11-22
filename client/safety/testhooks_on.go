//go:build hopbits_unsafe_testing

package safety

// testHooksEnabled reports whether the unsafe end-to-end test hooks are
// compiled in. This file is built only with the hopbits_unsafe_testing tag,
// which production binaries never set.
const testHooksEnabled = true
