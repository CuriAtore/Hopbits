package kit

import "testing"

func TestUnsafeTestPort(t *testing.T) {
	cases := []struct {
		port uint16
		test bool // opened in the unsafe test build
	}{
		{0, false}, {22, false}, {80, false}, {443, false}, {8080, false},
		{8443, false}, {32767, false}, {32768, true}, {50000, true}, {65535, true},
	}
	for _, tc := range cases {
		want := unsafeTestHooks && tc.test
		if got := UnsafeTestPort(tc.port); got != want {
			t.Errorf("UnsafeTestPort(%d) = %v, want %v", tc.port, got, want)
		}
	}
}

func TestUnsafeTestPortIsClosedInProductionBuilds(t *testing.T) {
	if unsafeTestHooks {
		t.Skip("this is the unsafe test build")
	}
	for p := 0; p <= 65535; p++ {
		if UnsafeTestPort(uint16(p)) {
			t.Fatalf("a production build opens port %d", p)
		}
	}
}
