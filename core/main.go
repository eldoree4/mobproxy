package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type SecurityScanner struct {
	PayloadGenerator *PayloadGenerator
	RequestMutator   *RequestMutator
	ResponseDiff     *ResponseDiff
	ExploitVerifier  *ExploitVerifier
	ScanResults      []ScanResult
}

type ScanResult struct {
	URL               string
	Timestamp         time.Time
	BaselineResponse  *ResponseData
	Vulnerabilities   []Vulnerability
	VerifiedExploits  []*VerificationResult
	Report            string
}

type Vulnerability struct {
	Type         string
	Request      *RequestData
	Response     *ResponseData
	Differences  *DiffResult
	Verification *VerificationResult
	PayloadInfo  *PayloadInfo
}

func NewSecurityScanner() *SecurityScanner {
	return &SecurityScanner{
		PayloadGenerator: NewPayloadGenerator(),
		RequestMutator:   NewRequestMutator(),
		ResponseDiff:     NewResponseDiff(),
		ExploitVerifier:  NewExploitVerifier(),
	}
}

func (sc *SecurityScanner) ScanURL(url, method string, headers map[string]string, data interface{}) (*ScanResult, error) {
	fmt.Printf("[*] Starting scan for %s\n", url)
	
	// Create baseline request
	baselineRequest, err := sc.createBaselineRequest(url, method, headers, data)
	if err != nil {
		return nil, err
	}
	
	// Get baseline response
	fmt.Printf("[*] Getting baseline response...\n")
	ctx := context.Background()
	baselineResponse, err := sc.RequestMutator.ExecuteRequest(ctx, baselineRequest)
	if err != nil {
		return nil, err
	}
	
	// Generate mutations and test
	fmt.Printf("[*] Generating and testing mutations...\n")
	requestText := sc.requestToText(baselineRequest)
	mutationResults := sc.RequestMutator.GenerateAllMutations(requestText, nil)
	
	var vulnerabilities []Vulnerability
	var verifiedExploits []*VerificationResult
	
	// Analyze each mutation
	for i, result := range mutationResults {
		fmt.Printf("\r[*] Testing mutation %d/%d", i+1, len(mutationResults))
		
		if result.Response.Error != "" {
			continue
		}
		
		// Compare with baseline
		differences := sc.ResponseDiff.CompareResponses(
			baselineResponse,
			result.Response,
			result.Request.PayloadInfo,
		)
		
		// Check for potential vulnerabilities
		if len(differences.PotentialVulns) > 0 {
			for _, vulnType := range differences.PotentialVulns {
				// Verify vulnerability
				verification := sc.ExploitVerifier.VerifyVulnerability(
					vulnType,
					result.Request,
					result.Response,
					result.Request.PayloadInfo,
					sc.RequestMutator,
				)
				
				if verification.Verified {
					vuln := Vulnerability{
						Type:         vulnType,
						Request:      result.Request,
						Response:     result.Response,
						Differences:  differences,
						Verification: verification,
						PayloadInfo:  result.Request.PayloadInfo,
					}
					vulnerabilities = append(vulnerabilities, vuln)
					
					if verification.ExploitPossible {
						verifiedExploits = append(verifiedExploits, verification)
					}
				}
			}
		}
	}
	
	fmt.Printf("\n[*] Scan completed!\n")
	
	// Generate report
	report := sc.generateScanReport(url, baselineResponse, vulnerabilities, verifiedExploits)
	
	result := &ScanResult{
		URL:               url,
		Timestamp:         time.Now(),
		BaselineResponse:  baselineResponse,
		Vulnerabilities:   vulnerabilities,
		VerifiedExploits:  verifiedExploits,
		Report:            report,
	}
	
	sc.ScanResults = append(sc.ScanResults, *result)
	return result, nil
}

func (sc *SecurityScanner) createBaselineRequest(url, method string, headers map[string]string, data interface{}) (*RequestData, error) {
	if headers == nil {
		headers = map[string]string{
			"User-Agent": "SecurityScanner/1.0",
			"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		}
	}
	
	var body string
	if data != nil {
		switch d := data.(type) {
		case string:
			body = d
		case map[string]interface{}:
			jsonData, err := json.Marshal(d)
			if err != nil {
				return nil, err
			}
			body = string(jsonData)
		default:
			jsonData, err := json.Marshal(d)
			if err != nil {
				return nil, err
			}
			body = string(jsonData)
		}
	}
	
	return &RequestData{
		Method:  method,
		URL:     url,
		Headers: headers,
		Body:    body,
	}, nil
}

func (sc *SecurityScanner) requestToText(request *RequestData) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("%s %s HTTP/1.1", request.Method, request.URL))
	
	for key, value := range request.Headers {
		lines = append(lines, fmt.Sprintf("%s: %s", key, value))
	}
	
	lines = append(lines, "")
	
	if request.Body != "" {
		lines = append(lines, request.Body)
	}
	
	return strings.Join(lines, "\n")
}

func (sc *SecurityScanner) generateScanReport(url string, baseline *ResponseData,
	vulnerabilities []Vulnerability, exploits []*VerificationResult) string {
	
	var report strings.Builder
	
	report.WriteString(strings.Repeat("=", 80) + "\n")
	report.WriteString("SECURITY SCAN REPORT\n")
	report.WriteString(strings.Repeat("=", 80) + "\n")
	report.WriteString(fmt.Sprintf("URL: %s\n", url))
	report.WriteString(fmt.Sprintf("Scan Time: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString(fmt.Sprintf("Baseline Status: %d\n", baseline.StatusCode))
	
	report.WriteString("\n" + strings.Repeat("=", 80) + "\n")
	report.WriteString("VULNERABILITY SUMMARY\n")
	report.WriteString(strings.Repeat("=", 80) + "\n")
	report.WriteString(fmt.Sprintf("Total Vulnerabilities Found: %d\n", len(vulnerabilities)))
	report.WriteString(fmt.Sprintf("Confirmed Exploitable: %d\n", len(exploits)))
	
	// Group by vulnerability type
	vulnTypes := make(map[string]int)
	for _, vuln := range vulnerabilities {
		vulnTypes[vuln.Type]++
	}
	
	if len(vulnTypes) > 0 {
		report.WriteString("\nVulnerability Breakdown:\n")
		for vulnType, count := range vulnTypes {
			report.WriteString(fmt.Sprintf("  %s: %d\n", vulnType, count))
		}
	}
	
	// Detailed findings
	if len(vulnerabilities) > 0 {
		report.WriteString("\n" + strings.Repeat("=", 80) + "\n")
		report.WriteString("DETAILED FINDINGS\n")
		report.WriteString(strings.Repeat("=", 80) + "\n")
		
		for i, vuln := range vulnerabilities {
			report.WriteString(fmt.Sprintf("\n%d. %s\n", i+1, vuln.Type))
			report.WriteString(fmt.Sprintf("   Location: %s\n", vuln.PayloadInfo.Location))
			report.WriteString(fmt.Sprintf("   Parameter: %s\n", vuln.PayloadInfo.Parameter))
			report.WriteString(fmt.Sprintf("   Payload: %s...\n", truncate(vuln.PayloadInfo.Payload, 50)))
			report.WriteString(fmt.Sprintf("   Confidence: %.1f%%\n", vuln.Verification.Confidence*100))
			report.WriteString(fmt.Sprintf("   Exploitable: %v\n", vuln.Verification.ExploitPossible))
			
			if len(vuln.Verification.Evidence) > 0 {
				report.WriteString("   Evidence:\n")
				for j, evidence := range vuln.Verification.Evidence {
					if j < 2 {
						report.WriteString(fmt.Sprintf("     - %s\n", evidence))
					}
				}
			}
		}
	}
	
	// Recommendations
	report.WriteString("\n" + strings.Repeat("=", 80) + "\n")
	report.WriteString("RECOMMENDATIONS\n")
	report.WriteString(strings.Repeat("=", 80) + "\n")
	
	if len(vulnerabilities) == 0 {
		report.WriteString("\n✅ No vulnerabilities found. Maintain current security practices.\n")
	} else {
		report.WriteString("\n🔴 Immediate Actions Required:\n")
		
		uniqueRecs := make(map[string]bool)
		for _, vuln := range vulnerabilities {
			rec := vuln.Verification.Recommendation
			if rec != "" {
				uniqueRecs[rec] = true
			}
		}
		
		for rec := range uniqueRecs {
			report.WriteString(fmt.Sprintf("  • %s\n", rec))
		}
		
		report.WriteString("\n🟡 General Security Recommendations:\n")
		report.WriteString("  • Implement Web Application Firewall (WAF)\n")
		report.WriteString("  • Regular security testing and code reviews\n")
		report.WriteString("  • Keep all software updated\n")
		report.WriteString("  • Implement proper logging and monitoring\n")
	}
	
	return report.String()
}

func (sc *SecurityScanner) ExportResults(format, filename string) error {
	if filename == "" {
		timestamp := time.Now().Format("20060102_150405")
		filename = fmt.Sprintf("scan_results_%s", timestamp)
	}
	
	switch strings.ToLower(format) {
	case "json":
		data, err := json.MarshalIndent(sc.ScanResults, "", "  ")
		if err != nil {
			return err
		}
		
		filepath := filename + ".json"
		return os.WriteFile(filepath, data, 0644)
		
	case "txt":
		filepath := filename + ".txt"
		file, err := os.Create(filepath)
		if err != nil {
			return err
		}
		defer file.Close()
		
		for _, result := range sc.ScanResults {
			file.WriteString(result.Report)
			file.WriteString("\n\n" + strings.Repeat("=", 80) + "\n\n")
		}
		
		return nil
		
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func main() {
	// Initialize scanner
	scanner := NewSecurityScanner()
	
	// Example usage
	fmt.Println("Security Scanner Demo")
	fmt.Println(strings.Repeat("=", 50))
	
	// 1. Generate payloads
	fmt.Println("\n1. Generating SQL Injection Payloads:")
	payloadGen := NewPayloadGenerator()
	sqlPayloads := payloadGen.GenerateSQLPayloads()
	for i := 0; i < 3 && i < len(sqlPayloads); i++ {
		fmt.Printf("   - %s\n", sqlPayloads[i])
	}
	
	// 2. Parse and mutate request
	fmt.Println("\n2. Parsing HTTP Request:")
	requestMutator := NewRequestMutator()
	sampleRequest := `GET /search.php?q=test HTTP/1.1
Host: example.com
User-Agent: TestAgent

`
	parsed, err := requestMutator.ParseRequest(sampleRequest)
	if err == nil {
		fmt.Printf("   Original URL: %s\n", parsed.URL)
		
		// Mutate query params
		mutations := requestMutator.MutateQueryParams(parsed, SQL)
		fmt.Printf("   Generated %d mutations\n", len(mutations))
	}
	
	// 3. Compare responses
	fmt.Println("\n3. Response Comparison:")
	responseDiff := NewResponseDiff()
	baseline := &ResponseData{
		StatusCode: 200,
		Body:       "Normal response",
	}
	mutated := &ResponseData{
		StatusCode: 500,
		Body:       "SQL Error: syntax error",
	}
	diff := responseDiff.CompareResponses(baseline, mutated, nil)
	fmt.Printf("   Anomaly Score: %.2f\n", diff.AnomalyScore)
	
	// 4. Verify exploit
	fmt.Println("\n4. Exploit Verification:")
	exploitVerifier := NewExploitVerifier()
	verification := exploitVerifier.VerifyVulnerability(
		"SQL_INJECTION",
		&RequestData{Method: "GET", URL: "http://example.com"},
		&ResponseData{StatusCode: 500, Body: "SQL Error"},
		&PayloadInfo{Type: "sql", Payload: "' OR '1'='1"},
		requestMutator,
	)
	fmt.Printf("   Verified: %v\n", verification.Verified)
	fmt.Printf("   Confidence: %.1f%%\n", verification.Confidence*100)
	
	// 5. Complete scan example (commented out for safety)
	/*
	fmt.Println("\n5. Complete Scan Example:")
	result, err := scanner.ScanURL(
		"http://testphp.vulnweb.com/",
		"GET",
		map[string]string{
			"User-Agent": "SecurityScanner/1.0",
			"Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
		nil,
	)
	
	if err == nil {
		fmt.Println("\n" + result.Report)
		scanner.ExportResults("txt", "")
	}
	*/
	
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Demo completed successfully!")
	fmt.Println("Note: Actual scanning requires proper authorization.")
}
