package plugins

import (
	"strings"
	"mobproxy/core"
)

type XSSTest struct{}

func (x *XSSTest) Name() string { return "Reflection Test (safe)" }

func (x *XSSTest) OnPassiveScan(req, resp string) []core.Finding {
	return nil
}

func (x *XSSTest) OnActiveScan(req *core.RawRequest) []core.Finding {
	var out []core.Finding

	marker := "MOBPROXY_REFLECT_TEST"
	resp, _ := core.SendWithMarker(req, marker)

	if strings.Contains(resp, marker) {
		out = append(out, core.Finding{
			Type:    "Possible Reflection",
			Detail:  "Input reflected in response",
			Request: req.Raw,
		})
	}
	return out
}

func init() {
	core.RegisterPlugin(&XSSTest{})
}
