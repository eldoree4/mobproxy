package core

import (
	"strings"
)

func ActiveScan(req *RawRequest) {
	// run all plugins
	RunActive(req)
}

// helper aman: kirim request dengan marker
func SendWithMarker(req *RawRequest, marker string) (string, error) {
	mod := strings.ReplaceAll(req.Raw, "=", "="+marker)
	return SendRaw(mod)
}
