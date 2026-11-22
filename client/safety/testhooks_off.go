//go:build !hopbits_unsafe_testing

package safety

// testHooksEnabled reports whether the unsafe end-to-end test hooks are
// compiled in. In every build without the hopbits_unsafe_testing tag the
// Config test fields are rejected and no address or port may bypass the
// compiled rules.
const testHooksEnabled = false
