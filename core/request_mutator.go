package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type RequestData struct {
	Method      string
	URL         string
	OriginalURL string
	Headers     map[string]string
	Body        string
	QueryParams url.Values
	Path        string
	ParsedURL   *url.URL
	PayloadInfo *PayloadInfo
}

type PayloadInfo struct {
	Location      string
	Parameter     string
	Payload       string
	Type          string
	OriginalValue string
	OriginalPath  string
}

type ResponseData struct {
	StatusCode   int
	Headers      http.Header
	Body         string
	ResponseTime time.Duration
	Size         int64
	FinalURL     string
	History      []string
	Error        string
}

type RequestMutator struct {
	PayloadGenerator *PayloadGenerator
	HTTPClient       *http.Client
}

func NewRequestMutator() *RequestMutator {
	// Create HTTP client with custom transport for testing
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Warning: Only for testing!
	}
	
	return &RequestMutator{
		PayloadGenerator: NewPayloadGenerator(),
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (rm *RequestMutator) ParseRequest(requestText string) (*RequestData, error) {
	lines := strings.Split(strings.TrimSpace(requestText), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}
	
	// Parse request line
	requestLine := strings.Fields(lines[0])
	if len(requestLine) < 3 {
		return nil, fmt.Errorf("invalid request line")
	}
	
	method := requestLine[0]
	rawURL := requestLine[1]
	httpVersion := requestLine[2]
	
	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	
	// Parse headers
	headers := make(map[string]string)
	bodyStart := 0
	
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			bodyStart = i + 1
			break
		}
		
		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}
	
	// Parse body
	var body string
	if bodyStart < len(lines) {
		body = strings.Join(lines[bodyStart:], "\n")
	}
	
	// Parse query parameters
	queryParams := parsedURL.Query()
	
	return &RequestData{
		Method:      method,
		URL:         rawURL,
		OriginalURL: rawURL,
		Headers:     headers,
		Body:        body,
		QueryParams: queryParams,
		Path:        parsedURL.Path,
		ParsedURL:   parsedURL,
	}, nil
}

func (rm *RequestMutator) MutateQueryParams(requestData *RequestData, payloadType PayloadType) []*RequestData {
	var mutations []*RequestData
	
	if requestData.QueryParams == nil || len(requestData.QueryParams) == 0 {
		return mutations
	}
	
	payloads := rm.PayloadGenerator.GetPayloadsByType(payloadType)
	
	for paramName, values := range requestData.QueryParams {
		if len(values) == 0 {
			continue
		}
		
		originalValue := values[0]
		
		for _, payload := range payloads {
			// Create copy of request data
			mutated := rm.copyRequestData(requestData)
			
			// Update query parameter
			mutated.QueryParams.Set(paramName, payload)
			
			// Rebuild URL
			parsed := mutated.ParsedURL
			parsed.RawQuery = mutated.QueryParams.Encode()
			mutated.URL = parsed.String()
			
			// Set payload info
			mutated.PayloadInfo = &PayloadInfo{
				Location:      "query",
				Parameter:     paramName,
				Payload:       payload,
				Type:          string(payloadType),
				OriginalValue: originalValue,
			}
			
			mutations = append(mutations, mutated)
		}
	}
	
	return mutations
}

func (rm *RequestMutator) MutateBodyParams(requestData *RequestData, payloadType PayloadType) []*RequestData {
	var mutations []*RequestData
	
	contentType := requestData.Headers["Content-Type"]
	
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Parse form data
		bodyParams, err := url.ParseQuery(requestData.Body)
		if err != nil {
			return mutations
		}
		
		payloads := rm.PayloadGenerator.GetPayloadsByType(payloadType)
		
		for paramName, values := range bodyParams {
			if len(values) == 0 {
				continue
			}
			
			originalValue := values[0]
			
			for _, payload := range payloads {
				mutated := rm.copyRequestData(requestData)
				
				// Update body parameter
				bodyParamsCopy := url.Values{}
				for k, v := range bodyParams {
					bodyParamsCopy[k] = v
				}
				bodyParamsCopy.Set(paramName, payload)
				
				mutated.Body = bodyParamsCopy.Encode()
				mutated.PayloadInfo = &PayloadInfo{
					Location:      "body",
					Parameter:     paramName,
					Payload:       payload,
					Type:          string(payloadType),
					OriginalValue: originalValue,
				}
				
				mutations = append(mutations, mutated)
			}
		}
		
	} else if strings.Contains(contentType, "application/json") {
		// Parse JSON
		var jsonData interface{}
		if err := json.Unmarshal([]byte(requestData.Body), &jsonData); err == nil {
			mutations = rm.mutateJSON(jsonData, requestData, payloadType, "")
		}
	}
	
	return mutations
}

func (rm *RequestMutator) mutateJSON(data interface{}, baseRequest *RequestData, payloadType PayloadType, path string) []*RequestData {
	var mutations []*RequestData
	
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			currentPath := path
			if currentPath == "" {
				currentPath = key
			} else {
				currentPath = fmt.Sprintf("%s.%s", path, key)
			}
			
			switch val := value.(type) {
			case string, float64, bool:
				// Create mutation for primitive values
				mutations = append(mutations, rm.createJSONMutation(baseRequest, currentPath, payloadType, val)...)
			default:
				// Recursively process nested structures
				mutations = append(mutations, rm.mutateJSON(value, baseRequest, payloadType, currentPath)...)
			}
		}
		
	case []interface{}:
		for i, item := range v {
			currentPath := fmt.Sprintf("%s[%d]", path, i)
			
			switch val := item.(type) {
			case string, float64, bool:
				mutations = append(mutations, rm.createJSONMutation(baseRequest, currentPath, payloadType, val)...)
			default:
				mutations = append(mutations, rm.mutateJSON(item, baseRequest, payloadType, currentPath)...)
			}
		}
	}
	
	return mutations
}

func (rm *RequestMutator) createJSONMutation(baseRequest *RequestData, path string, payloadType PayloadType, originalValue interface{}) []*RequestData {
	var mutations []*RequestData
	payloads := rm.PayloadGenerator.GetPayloadsByType(payloadType)
	
	for _, payload := range payloads {
		// Parse original JSON
		var jsonData interface{}
		if err := json.Unmarshal([]byte(baseRequest.Body), &jsonData); err != nil {
			continue
		}
		
		// Create mutated copy
		mutatedJSON := rm.modifyJSONValue(jsonData, path, payload)
		
		// Marshal back to string
		mutatedBody, err := json.Marshal(mutatedJSON)
		if err != nil {
			continue
		}
		
		// Create mutated request
		mutated := rm.copyRequestData(baseRequest)
		mutated.Body = string(mutatedBody)
		mutated.PayloadInfo = &PayloadInfo{
			Location:      "json_body",
			Parameter:     path,
			Payload:       payload,
			Type:          string(payloadType),
			OriginalValue: fmt.Sprintf("%v", originalValue),
		}
		
		mutations = append(mutations, mutated)
	}
	
	return mutations
}

func (rm *RequestMutator) modifyJSONValue(data interface{}, path string, newValue string) interface{} {
	parts := strings.Split(path, ".")
	
	var traverse func(interface{}, []string) interface{}
	traverse = func(current interface{}, parts []string) interface{} {
		if len(parts) == 0 {
			return newValue
		}
		
		part := parts[0]
		
		// Check if part is an array index
		if strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") {
			indexStr := strings.TrimPrefix(strings.TrimSuffix(part, "]"), "[")
			var index int
			fmt.Sscanf(indexStr, "%d", &index)
			
			if arr, ok := current.([]interface{}); ok && index < len(arr) {
				arr[index] = traverse(arr[index], parts[1:])
				return arr
			}
		} else {
			if m, ok := current.(map[string]interface{}); ok {
				if _, exists := m[part]; exists {
					m[part] = traverse(m[part], parts[1:])
				}
				return m
			}
		}
		
		return current
	}
	
	return traverse(data, parts)
}

func (rm *RequestMutator) MutateHeaders(requestData *RequestData, payloadType PayloadType) []*RequestData {
	var mutations []*RequestData
	
	payloads := rm.PayloadGenerator.GetPayloadsByType(payloadType)
	
	for headerName, originalValue := range requestData.Headers {
		for _, payload := range payloads {
			mutated := rm.copyRequestData(requestData)
			mutated.Headers[headerName] = payload
			
			mutated.PayloadInfo = &PayloadInfo{
				Location:      "header",
				Parameter:     headerName,
				Payload:       payload,
				Type:          string(payloadType),
				OriginalValue: originalValue,
			}
			
			mutations = append(mutations, mutated)
		}
	}
	
	return mutations
}

func (rm *RequestMutator) MutatePath(requestData *RequestData, payloadType PayloadType) []*RequestData {
	var mutations []*RequestData
	
	payloads := rm.PayloadGenerator.GetPayloadsByType(payloadType)
	
	for _, payload := range payloads {
		mutated := rm.copyRequestData(requestData)
		
		// Append payload to path
		originalPath := mutated.ParsedURL.Path
		var newPath string
		if !strings.HasSuffix(originalPath, "/") {
			newPath = fmt.Sprintf("%s/%s", originalPath, payload)
		} else {
			newPath = originalPath + payload
		}
		
		// Rebuild URL
		parsed := mutated.ParsedURL
		parsed.Path = newPath
		mutated.URL = parsed.String()
		
		mutated.PayloadInfo = &PayloadInfo{
			Location:     "path",
			Payload:      payload,
			Type:         string(payloadType),
			OriginalPath: originalPath,
		}
		
		mutations = append(mutations, mutated)
	}
	
	return mutations
}

func (rm *RequestMutator) copyRequestData(original *RequestData) *RequestData {
	copied := &RequestData{
		Method:      original.Method,
		URL:         original.URL,
		OriginalURL: original.OriginalURL,
		Body:        original.Body,
		Path:        original.Path,
	}
	
	// Deep copy headers
	copied.Headers = make(map[string]string)
	for k, v := range original.Headers {
		copied.Headers[k] = v
	}
	
	// Deep copy query params
	if original.QueryParams != nil {
		copied.QueryParams = url.Values{}
		for k, values := range original.QueryParams {
			copied.QueryParams[k] = append([]string{}, values...)
		}
	}
	
	// Copy parsed URL
	if original.ParsedURL != nil {
		copiedURL, _ := url.Parse(original.ParsedURL.String())
		copied.ParsedURL = copiedURL
	}
	
	return copied
}

func (rm *RequestMutator) ExecuteRequest(ctx context.Context, requestData *RequestData) (*ResponseData, error) {
	// Parse URL
	parsedURL, err := url.Parse(requestData.URL)
	if err != nil {
		return nil, err
	}
	
	// Create request
	var reqBody io.Reader
	if requestData.Body != "" {
		reqBody = strings.NewReader(requestData.Body)
	}
	
	req, err := http.NewRequestWithContext(ctx, requestData.Method, parsedURL.String(), reqBody)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	for key, value := range requestData.Headers {
		req.Header.Set(key, value)
	}
	
	// Set Content-Length if body exists
	if requestData.Body != "" {
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(requestData.Body)))
	}
	
	// Add default headers if not present
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "SecurityScanner/1.0")
	}
	
	startTime := time.Now()
	
	// Execute request
	resp, err := rm.HTTPClient.Do(req)
	if err != nil {
		return &ResponseData{
			Error:        err.Error(),
			ResponseTime: time.Since(startTime),
		}, nil
	}
	defer resp.Body.Close()
	
	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	// Get response history
	var history []string
	if resp.Request != nil && resp.Request.URL != nil {
		history = append(history, resp.Request.URL.String())
	}
	
	return &ResponseData{
		StatusCode:   resp.StatusCode,
		Headers:      resp.Header,
		Body:         string(bodyBytes),
		ResponseTime: time.Since(startTime),
		Size:         int64(len(bodyBytes)),
		FinalURL:     resp.Request.URL.String(),
		History:      history,
	}, nil
}

func (rm *RequestMutator) GenerateAllMutations(requestText string, mutationTypes []string) []struct {
	Request  *RequestData
	Response *ResponseData
} {
	if len(mutationTypes) == 0 {
		mutationTypes = []string{"query", "body", "headers", "path"}
	}
	
	requestData, err := rm.ParseRequest(requestText)
	if err != nil {
		return nil
	}
	
	var allMutations []struct {
		Request  *RequestData
		Response *ResponseData
	}
	
	ctx := context.Background()
	
	for _, mtype := range mutationTypes {
		switch mtype {
		case "query":
			payloadTypes := []PayloadType{SQL, XSS, CommandInj, PathTraversal}
			for _, payloadType := range payloadTypes {
				mutations := rm.MutateQueryParams(requestData, payloadType)
				for _, mutation := range mutations {
					response, err := rm.ExecuteRequest(ctx, mutation)
					if err == nil {
						allMutations = append(allMutations, struct {
							Request  *RequestData
							Response *ResponseData
						}{mutation, response})
					}
				}
			}
			
		case "body":
			payloadTypes := []PayloadType{SQL, XSS, CommandInj}
			for _, payloadType := range payloadTypes {
				mutations := rm.MutateBodyParams(requestData, payloadType)
				for _, mutation := range mutations {
					response, err := rm.ExecuteRequest(ctx, mutation)
					if err == nil {
						allMutations = append(allMutations, struct {
							Request  *RequestData
							Response *ResponseData
						}{mutation, response})
					}
				}
			}
			
		case "headers":
			payloadTypes := []PayloadType{XSS, SQL}
			for _, payloadType := range payloadTypes {
				mutations := rm.MutateHeaders(requestData, payloadType)
				for _, mutation := range mutations {
					response, err := rm.ExecuteRequest(ctx, mutation)
					if err == nil {
						allMutations = append(allMutations, struct {
							Request  *RequestData
							Response *ResponseData
						}{mutation, response})
					}
				}
			}
			
		case "path":
			payloadTypes := []PayloadType{PathTraversal, FUZZ}
			for _, payloadType := range payloadTypes {
				mutations := rm.MutatePath(requestData, payloadType)
				for _, mutation := range mutations {
					response, err := rm.ExecuteRequest(ctx, mutation)
					if err == nil {
						allMutations = append(allMutations, struct {
							Request  *RequestData
							Response *ResponseData
						}{mutation, response})
					}
				}
			}
		}
	}
	
	return allMutations
}
