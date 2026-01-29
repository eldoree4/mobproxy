package core

import (
	"regexp"
	"strings"
)

type Finding struct {
	Type    string
	Detail  string
	Request string
}

var Findings []Finding

var (
	reSQL  = regexp.MustCompile(`(?i)(sql syntax|mysql|odbc|sqlite|psql|ora-\d+)`)
	reXSS  = regexp.MustCompile(`(?i)(<script|onerror=|alert\()`)
	reLFI  = regexp.MustCompile(`(?i)(root:x:|/etc/passwd|boot.ini)`)
	reSSTI = regexp.MustCompile(`(?i)({{.*}}|<%.*%>)`)
	reRED  = regexp.MustCompile(`(?i)(location:.*http)`)
)

func ScanResponse(reqRaw, resp string) {
	body := strings.ToLower(resp)

	check := func(re *regexp.Regexp, t string) {
		if re.MatchString(body) {
			Findings = append(Findings, Finding{
				Type:    t,
				Detail: "Pattern matched",
				Request: reqRaw,
			})
		}
	}

	check(reSQL, "Possible SQL Injection")
	check(reXSS, "Possible XSS")
	check(reLFI, "Possible LFI")
	check(reSSTI, "Possible SSTI")
	check(reRED, "Possible Open Redirect")
}
