package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type ResponseDiff struct {
	Thresholds map[string]float64
	VulnKeywords map[string][]string
}

func NewResponseDiff() *ResponseDiff {
	rd := &ResponseDiff{
		Thresholds: map[string]float64{
			"status_code":     0,
			"body_length":     0.2, // 20% difference threshold
			"response_time":   2.0, // 2x slower
			"keyword_matches": 3,   // Minimum keyword matches
			"similarity":      0.8, // 80% similarity
		},
		VulnKeywords: map[string][]string{
			"sql": {
				"sql", "syntax", "mysql", "postgresql", "oracle", "database",
				"warning", "error", "exception", "unclosed", "quote",
				"you have an error", "select", "union", "from", "where",
				"order by", "group by", "column", "table",
			},
			"xss": {
				"script", "alert", "onerror", "onload", "onclick",
				"javascript:", "<script>", "</script>", "img", "iframe",
				"svg", "body", "document.cookie", "window.location",
			},
			"command": {
				"bin/bash", "bin/sh", "cmd.exe", "powershell",
				"root:", "uid=", "gid=", "groups=", "etc/passwd",
				"system32", "windows", "linux", "unix", "permission denied",
				"command not found", "syntax error", "sh:",
			},
			"path_traversal": {
				"root:", "daemon:", "bin/", "etc/passwd", "etc/shadow",
				"boot.ini", "win.ini", "system.ini", "hosts", "proc/",
				"var/log/", "access.log", "error.log", "no such file",
				"permission denied", "directory traversal",
			},
		},
	}
	return rd
}

type DiffResult struct {
	StatusCodeDiff      bool
	StatusCodeValues    [2]int
	BodyLengthDiff      float64
	ResponseTimeDiff    float64
	HeaderDiffs         HeaderDiff
	BodySimilarity      float64
	KeywordMatches      map[string][]KeywordMatch
	PotentialVulns      []string
	AnomalyScore        float64
	HTMLStructureDiff   HTMLDiff
}

type KeywordMatch struct {
	Keyword string
	Position int
}

type HeaderDiff struct {
	Added    map[string]string
	Removed  map[string]string
	Modified map[string][2]string
}

type HTMLDiff struct {
	TagSimilarity   float64
	TextSimilarity  float64
	TagCountDiff    int
	HasFormChanges  bool
	HasInputChanges bool
}

func (rd *ResponseDiff) CompareResponses(baseline, mutated *ResponseData, payloadInfo *PayloadInfo) *DiffResult {
	result := &DiffResult{
		StatusCodeValues: [2]int{baseline.StatusCode, mutated.StatusCode},
		KeywordMatches:   make(map[string][]KeywordMatch),
	}
	
	// Compare status code
	result.StatusCodeDiff = baseline.StatusCode != mutated.StatusCode
	
	// Compare body length
	result.BodyLengthDiff = rd.calculateLengthDiff(len(baseline.Body), len(mutated.Body))
	
	// Compare response time
	result.ResponseTimeDiff = rd.calculateTimeDiff(baseline.ResponseTime, mutated.ResponseTime)
	
	// Compare headers
	result.HeaderDiffs = rd.compareHeaders(baseline.Headers, mutated.Headers)
	
	// Calculate similarity
	result.BodySimilarity = rd.calculateSimilarity(baseline.Body, mutated.Body)
	
	// Check for vulnerability indicators
	if payloadInfo != nil {
		payloadType := payloadInfo.Type
		result.KeywordMatches[payloadType] = rd.findKeywords(mutated.Body, payloadType)
		
		// Calculate anomaly score
		result.AnomalyScore = rd.calculateAnomalyScore(result, payloadType)
		
		// Detect potential vulnerabilities
		result.PotentialVulns = rd.detectVulnerabilities(result, payloadInfo, mutated.Body)
	}
	
	// Compare HTML structure if applicable
	if rd.isHTML(baseline.Body) {
		result.HTMLStructureDiff = rd.compareHTMLStructure(baseline.Body, mutated.Body)
	}
	
	return result
}

func (rd *ResponseDiff) calculateLengthDiff(len1, len2 int) float64 {
	if len1 == 0 {
		if len2 > 0 {
			return 1.0
		}
		return 0.0
	}
	
	diff := float64(abs(len1 - len2)) / float64(len1)
	if diff > 1.0 {
		return 1.0
	}
	return diff
}

func (rd *ResponseDiff) calculateTimeDiff(t1, t2 time.Duration) float64 {
	if t1 == 0 {
		if t2 > 0 {
			return 1.0
		}
		return 0.0
	}
	
	return float64(t2) / float64(t1)
}

func (rd *ResponseDiff) compareHeaders(h1, h2 http.Header) HeaderDiff {
	diff := HeaderDiff{
		Added:    make(map[string]string),
		Removed:  make(map[string]string),
		Modified: make(map[string][2]string),
	}
	
	// Get all header keys
	h1Keys := make(map[string]bool)
	h2Keys := make(map[string]bool)
	
	for k := range h1 {
		h1Keys[strings.ToLower(k)] = true
	}
	for k := range h2 {
		h2Keys[strings.ToLower(k)] = true
	}
	
	// Find added headers
	for k := range h2Keys {
		if !h1Keys[k] {
			diff.Added[k] = h2.Get(k)
		}
	}
	
	// Find removed headers
	for k := range h1Keys {
		if !h2Keys[k] {
			diff.Removed[k] = h1.Get(k)
		}
	}
	
	// Find modified headers
	for k := range h1Keys {
		if h2Keys[k] {
			v1 := h1.Get(k)
			v2 := h2.Get(k)
			if v1 != v2 {
				diff.Modified[k] = [2]string{v1, v2}
			}
		}
	}
	
	return diff
}

func (rd *ResponseDiff) calculateSimilarity(text1, text2 string) float64 {
	if len(text1) == 0 || len(text2) == 0 {
		return 0.0
	}
	
	// Simple similarity calculation using Levenshtein distance ratio
	// For production, consider using a proper diff library
	distance := levenshteinDistance(text1, text2)
	maxLen := max(len(text1), len(text2))
	
	if maxLen == 0 {
		return 1.0
	}
	
	return 1.0 - float64(distance)/float64(maxLen)
}

func (rd *ResponseDiff) findKeywords(text, payloadType string) []KeywordMatch {
	var matches []KeywordMatch
	
	if keywords, ok := rd.VulnKeywords[payloadType]; ok {
		textLower := strings.ToLower(text)
		
		for _, keyword := range keywords {
			keywordLower := strings.ToLower(keyword)
			idx := strings.Index(textLower, keywordLower)
			if idx != -1 {
				matches = append(matches, KeywordMatch{
					Keyword:  keyword,
					Position: idx,
				})
			}
		}
	}
	
	return matches
}

func (rd *ResponseDiff) calculateAnomalyScore(diff *DiffResult, payloadType string) float64 {
	score := 0.0
	
	// Status code difference
	if diff.StatusCodeDiff {
		statusDiff := abs(diff.StatusCodeValues[0] - diff.StatusCodeValues[1])
		if statusDiff >= 400 {
			score += 0.4
		} else if statusDiff >= 300 {
			score += 0.2
		} else {
			score += 0.1
		}
	}
	
	// Body length difference
	if diff.BodyLengthDiff > rd.Thresholds["body_length"] {
		score += min(0.3, diff.BodyLengthDiff)
	}
	
	// Response time difference
	if diff.ResponseTimeDiff > rd.Thresholds["response_time"] {
		score += 0.2
	}
	
	// Keyword matches
	keywordMatches := len(diff.KeywordMatches[payloadType])
	if float64(keywordMatches) >= rd.Thresholds["keyword_matches"] {
		score += min(0.3, float64(keywordMatches)*0.1)
	}
	
	// Low similarity
	if diff.BodySimilarity < rd.Thresholds["similarity"] {
		score += 0.1
	}
	
	return min(1.0, score)
}

func (rd *ResponseDiff) detectVulnerabilities(diff *DiffResult, payloadInfo *PayloadInfo, mutatedBody string) []string {
	var vulnerabilities []string
	payloadType := payloadInfo.Type
	anomalyScore := diff.AnomalyScore
	
	switch payloadType {
	case "sql":
		if anomalyScore > 0.5 {
			keywordMatches := len(diff.KeywordMatches["sql"])
			if keywordMatches >= 2 {
				vulnerabilities = append(vulnerabilities, "SQL_INJECTION")
			}
		}
		
	case "xss":
		if diff.BodySimilarity < 0.7 {
			if strings.Contains(mutatedBody, payloadInfo.Payload) {
				vulnerabilities = append(vulnerabilities, "XSS_REFLECTED")
			}
		}
		
		keywordMatches := len(diff.KeywordMatches["xss"])
		if keywordMatches >= 3 {
			vulnerabilities = append(vulnerabilities, "XSS_POTENTIAL")
		}
		
	case "command":
		if diff.ResponseTimeDiff > 3.0 {
			vulnerabilities = append(vulnerabilities, "COMMAND_INJECTION_TIME_BASED")
		}
		
		keywordMatches := len(diff.KeywordMatches["command"])
		if keywordMatches >= 2 {
			vulnerabilities = append(vulnerabilities, "COMMAND_INJECTION")
		}
		
	case "path_traversal":
		keywordMatches := len(diff.KeywordMatches["path_traversal"])
		if keywordMatches >= 1 {
			vulnerabilities = append(vulnerabilities, "PATH_TRAVERSAL")
		}
		
		if rd.containsFileContents(mutatedBody) {
			vulnerabilities = append(vulnerabilities, "PATH_TRAVERSAL_CONFIRMED")
		}
	}
	
	// Generic anomalies
	if anomalyScore > 0.7 {
		vulnerabilities = append(vulnerabilities, "HIGH_ANOMALY")
	} else if anomalyScore > 0.5 {
		vulnerabilities = append(vulnerabilities, "MEDIUM_ANOMALY")
	} else if anomalyScore > 0.3 {
		vulnerabilities = append(vulnerabilities, "LOW_ANOMALY")
	}
	
	return vulnerabilities
}

func (rd *ResponseDiff) isHTML(text string) bool {
	return strings.Contains(text, "<") && strings.Contains(text, ">")
}

func (rd *ResponseDiff) compareHTMLStructure(html1, html2 string) HTMLDiff {
	// Simple HTML comparison
	// For production, consider using an HTML parser
	
	tagCount1 := len(regexp.MustCompile(`<[^>]+>`).FindAllString(html1, -1))
	tagCount2 := len(regexp.MustCompile(`<[^>]+>`).FindAllString(html2, -1))
	
	formCount1 := strings.Count(html1, "<form")
	formCount2 := strings.Count(html2, "<form")
	
	inputCount1 := strings.Count(html1, "<input")
	inputCount2 := strings.Count(html2, "<input")
	
	// Extract text content (simple approach)
	text1 := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(html1, " ")
	text2 := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(html2, " ")
	
	return HTMLDiff{
		TagSimilarity:   rd.calculateSimilarity(html1, html2),
		TextSimilarity:  rd.calculateSimilarity(text1, text2),
		TagCountDiff:    tagCount1 - tagCount2,
		HasFormChanges:  formCount1 != formCount2,
		HasInputChanges: inputCount1 != inputCount2,
	}
}

func (rd *ResponseDiff) containsFileContents(text string) bool {
	patterns := []string{
		`root:.*:0:0:`,
		`\[boot loader\]`,
		`\[fonts\]`,
		`127\.0\.0\.1\s+localhost`,
		`BEGIN CERTIFICATE`,
		`<\?xml version`,
		`{"\w+":`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(text) {
			return true
		}
	}
	
	return false
}

func (rd *ResponseDiff) GenerateDiffReport(baseline, mutated *ResponseData, diff *DiffResult) string {
	var report strings.Builder
	
	report.WriteString(strings.Repeat("=", 80) + "\n")
	report.WriteString("RESPONSE DIFF REPORT\n")
	report.WriteString(strings.Repeat("=", 80) + "\n")
	
	report.WriteString(fmt.Sprintf("\nBaseline Status Code: %d\n", baseline.StatusCode))
	report.WriteString(fmt.Sprintf("Mutated Status Code: %d\n", mutated.StatusCode))
	report.WriteString(fmt.Sprintf("Status Code Changed: %v\n", diff.StatusCodeDiff))
	
	report.WriteString(fmt.Sprintf("\nBaseline Body Length: %d\n", len(baseline.Body)))
	report.WriteString(fmt.Sprintf("Mutated Body Length: %d\n", len(mutated.Body)))
	report.WriteString(fmt.Sprintf("Length Difference Ratio: %.2f%%\n", diff.BodyLengthDiff*100))
	
	report.WriteString(fmt.Sprintf("\nBaseline Response Time: %v\n", baseline.ResponseTime))
	report.WriteString(fmt.Sprintf("Mutated Response Time: %v\n", mutated.ResponseTime))
	report.WriteString(fmt.Sprintf("Time Ratio: %.2fx\n", diff.ResponseTimeDiff))
	
	report.WriteString(fmt.Sprintf("\nResponse Similarity: %.2f%%\n", diff.BodySimilarity*100))
	
	if len(diff.PotentialVulns) > 0 {
		report.WriteString("\nPotential Vulnerabilities Found:\n")
		for _, vuln := range diff.PotentialVulns {
			report.WriteString(fmt.Sprintf("  - %s\n", vuln))
		}
	}
	
	for payloadType, matches := range diff.KeywordMatches {
		if len(matches) > 0 {
			report.WriteString(fmt.Sprintf("\n%s Keywords Found (%d):\n", strings.ToUpper(payloadType), len(matches)))
			for i, match := range matches {
				if i < 5 { // Show first 5
					report.WriteString(fmt.Sprintf("  - '%s' at position %d\n", match.Keyword, match.Position))
				}
			}
		}
	}
	
	report.WriteString(fmt.Sprintf("\nAnomaly Score: %.2f/1.0\n", diff.AnomalyScore))
	
	if diff.BodySimilarity < 0.9 {
		report.WriteString("\nSignificant Body Differences Detected\n")
	}
	
	return report.String()
}

// Helper functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func levenshteinDistance(s1, s2 string) int {
	// Implementation of Levenshtein distance
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}
	
	// Create matrix
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}
	
	// Calculate distance
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			matrix[i][j] = minInt(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	
	return matrix[len(s1)][len(s2)]
}

func minInt(values ...int) int {
	minVal := values[0]
	for _, v := range values[1:] {
		if v < minVal {
			minVal = v
		}
	}
	return minVal
}
