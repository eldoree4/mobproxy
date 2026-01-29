package core

func RunPassive(req, resp string) {
	for _, p := range plugins {
		findings := p.OnPassiveScan(req, resp)
		Findings = append(Findings, findings...)
	}
}

func RunActive(req *RawRequest) {
	for _, p := range plugins {
		findings := p.OnActiveScan(req)
		Findings = append(Findings, findings...)
	}
}
