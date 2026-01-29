package core

import "strings"

type RawRequest struct {
	Raw string
}

func ParseRawRequest(raw string) *RawRequest {
	return &RawRequest{Raw: raw}
}

func (r *RawRequest) WithPayload(payload string) string {
	return strings.ReplaceAll(r.Raw, "§", payload)
}
