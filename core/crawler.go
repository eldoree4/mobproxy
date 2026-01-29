package core

import (
	"regexp"
)

var linkRegex = regexp.MustCompile(`(?i)(href|src)=["']([^"'#]+)`)

var crawlQueue = make(chan string, 100)
var crawled = map[string]bool{}

func FeedCrawler(baseURL, body string) {
	matches := linkRegex.FindAllStringSubmatch(body, -1)
	for _, m := range matches {
		url := m[2]
		if !crawled[url] && InScope(url) {
			crawled[url] = true
			crawlQueue <- url
		}
	}
}

func StartCrawler() {
	go func() {
		for url := range crawlQueue {
			go func(u string) {
				req := BuildSimpleGET(u)
				resp, err := SendRaw(req.Raw)
				if err == nil {
					FeedCrawler(u, resp)
				}
			}(url)
		}
	}()
}
