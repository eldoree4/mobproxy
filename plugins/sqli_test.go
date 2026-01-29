package plugins

import (
	"strings"
	"mobproxy/core"
)

type SQLiTest struct{}

func (s *SQLiTest) Name() string { return "SQLi Test (safe)" }

func (s *SQLiTest) OnPassiveScan(req, resp string) []core.Finding {
	return nil
}

func (s *SQLiTest) OnActiveScan(req *core.RawRequest) []core.Finding {
	var out []core.Finding

	resp, err := core.SendWithMarker(req, "mobproxy_test")
	if err != nil {
		return nil
	}

	if strings.Contains(strings.ToLower(resp), "error") {
		out = append(out, core.Finding{
			Type:    "Possible Input Handling Issue",
			Detail:  "Response contains error after marker injection",
			Request: req.Raw,
		})
	}
	return out
}

func init() {
	core.RegisterPlugin(&SQLiTest{})
}

