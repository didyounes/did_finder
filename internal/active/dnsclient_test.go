package active

import (
	"reflect"
	"testing"
)

func TestNormalizeResolversAddsPortsAndDeduplicates(t *testing.T) {
	got := NormalizeResolvers([]string{
		"1.1.1.1",
		"udp://8.8.8.8:53",
		"1.1.1.1:53",
		"[2606:4700:4700::1111]",
		"",
	})
	want := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"[2606:4700:4700::1111]:53",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeResolvers() = %#v, want %#v", got, want)
	}
}
