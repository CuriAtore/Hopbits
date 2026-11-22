//go:build !hopbits_unsafe_testing

package kit

// unsafeTestHooks reports whether the unsafe end-to-end test hooks are
// compiled in. In every build without the hopbits_unsafe_testing tag each
// module checks its compiled ports itself, as well as the safety layer.
const unsafeTestHooks = false
