package core

func BuildSimpleGET(url string) *RawRequest {
	raw := "GET " + url + " HTTP/1.1\r\nHost: " + extractHost(url) + "\r\n\r\n"
	return ParseRawRequest(raw)
}

