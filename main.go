package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

type AuthConfig struct {
	SessionID string
	CSRFToken string
}

type LeetCodeGraphQLClient struct {
	client    *http.Client
	sessionID string
	csrfToken string
}

type SubmissionResponse struct {
	SubmissionID int64 `json:"submission_id"`
}

type SubmissionStatusResponse struct {
	StatusCode        int      `json:"status_code"`
	Lang              string   `json:"lang"`
	RunSuccess        bool     `json:"run_success"`
	RuntimeError      string   `json:"runtime_error"`
	FullRuntimeError  string   `json:"full_runtime_error"`
	StatusRuntime     string   `json:"status_runtime"`
	Memory            int64    `json:"memory"`
	QuestionID        string   `json:"question_id"`
	ElapsedTime       int      `json:"elapsed_time"`
	CompareResult     string   `json:"compare_result"`
	CodeOutput        string   `json:"code_output"`
	StdOutput         string   `json:"std_output"`
	LastTestcase      string   `json:"last_testcase"`
	ExpectedOutput    string   `json:"expected_output"`
	TaskFinishTime    int64    `json:"task_finish_time"`
	TaskName          string   `json:"task_name"`
	Finished          bool     `json:"finished"`
	TotalCorrect      int      `json:"total_correct"`
	TotalTestcases    int      `json:"total_testcases"`
	RuntimePercentile *float64 `json:"runtime_percentile"`
	StatusMemory      string   `json:"status_memory"`
	MemoryPercentile  *float64 `json:"memory_percentile"`
	PrettyLang        string   `json:"pretty_lang"`
	SubmissionID      string   `json:"submission_id"`
	StatusMsg         string   `json:"status_msg"`
	State             string   `json:"state"`
	CompileError      string   `json:"compile_error"`
}

type CodeSnippet struct {
	Lang     string `json:"lang"`
	LangSlug string `json:"langSlug"`
	Code     string `json:"code"`
}

type Problem struct {
	Title        string        `json:"title"`
	TitleSlug    string        `json:"titleSlug"`
	Difficulty   string        `json:"difficulty"`
	QuestionID   string        `json:"questionId"`
	Content      string        `json:"content"`
	TopicTags    []TagInfo     `json:"topicTags"`
	CodeSnippets []CodeSnippet `json:"codeSnippets"`
}

type TagInfo struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func NewLeetCodeGraphQLClient(auth *AuthConfig) *LeetCodeGraphQLClient {
	return &LeetCodeGraphQLClient{
		client:    &http.Client{Timeout: 30 * time.Second},
		sessionID: auth.SessionID,
		csrfToken: auth.CSRFToken,
	}
}

func (c *LeetCodeGraphQLClient) RefreshCSRFToken(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://leetcode.com/", nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
	req.Header.Set("Cookie", fmt.Sprintf("LEETCODE_SESSION=%s", c.sessionID))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Extract CSRF token from Set-Cookie header
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "csrftoken" {
			c.csrfToken = cookie.Value
			return nil
		}
	}

	// Try to extract from response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	bodyStr := string(body)
	if idx := strings.Index(bodyStr, `"csrfToken":"`); idx != -1 {
		start := idx + len(`"csrfToken":"`)
		end := strings.Index(bodyStr[start:], `"`)
		if end != -1 {
			c.csrfToken = bodyStr[start : start+end]
			return nil
		}
	}

	return fmt.Errorf("could not extract CSRF token")
}

func (c *LeetCodeGraphQLClient) GetProblemList(ctx context.Context, limit, skip int) ([]map[string]interface{}, error) {
	query := `
		query problemsetQuestionList($limit: Int, $skip: Int) {
			problemsetQuestionList(categorySlug: "all-code-essentials", limit: $limit, skip: $skip) {
				questions {
					titleSlug
					title
					difficulty
				}
			}
		}`
	variables := map[string]interface{}{"limit": limit, "skip": skip}
	resp := make(map[string]interface{})
	if err := c.postGraphQL(ctx, query, variables, &resp); err != nil {
		return nil, err
	}

	questions := resp["data"].(map[string]interface{})["problemsetQuestionList"].(map[string]interface{})["questions"].([]interface{})
	result := []map[string]interface{}{}
	for _, q := range questions {
		result = append(result, q.(map[string]interface{}))
	}
	return result, nil
}

func (c *LeetCodeGraphQLClient) GetProblem(ctx context.Context, titleSlug string) (map[string]interface{}, error) {
	query := `
		query getQuestionDetail($titleSlug: String!) {
			question(titleSlug: $titleSlug) {
				title
				titleSlug
				difficulty
				topicTags { name slug }
				codeSnippets { lang langSlug code }
				questionId
				content
			}
		}`
	variables := map[string]interface{}{"titleSlug": titleSlug}
	resp := make(map[string]interface{})
	if err := c.postGraphQL(ctx, query, variables, &resp); err != nil {
		return nil, err
	}
	return resp["data"].(map[string]interface{})["question"].(map[string]interface{}), nil
}

func (c *LeetCodeGraphQLClient) GetProblemStub(ctx context.Context, titleSlug, language string) (string, error) {
	problem, err := c.GetProblem(ctx, titleSlug)
	if err != nil {
		return "", err
	}

	codeSnippets, ok := problem["codeSnippets"].([]interface{})
	if !ok {
		return "", fmt.Errorf("no code snippets found for problem %s", titleSlug)
	}

	// Map common language names to LeetCode language slugs
	langMap := map[string][]string{
		"python":     {"python3", "python"},
		"python3":    {"python3", "python"},
		"java":       {"java"},
		"cpp":        {"cpp"},
		"c++":        {"cpp"},
		"javascript": {"javascript"},
		"js":         {"javascript"},
		"typescript": {"typescript"},
		"ts":         {"typescript"},
		"c":          {"c"},
		"csharp":     {"csharp"},
		"c#":         {"csharp"},
		"go":         {"golang"},
		"golang":     {"golang"},
		"rust":       {"rust"},
		"ruby":       {"ruby"},
		"swift":      {"swift"},
		"kotlin":     {"kotlin"},
		"scala":      {"scala"},
		"php":        {"php"},
	}

	targetLangs, exists := langMap[strings.ToLower(language)]
	if !exists {
		targetLangs = []string{strings.ToLower(language)}
	}

	// Find matching code snippet
	for _, snippet := range codeSnippets {
		snippetMap := snippet.(map[string]interface{})
		langSlug := strings.ToLower(snippetMap["langSlug"].(string))

		for _, targetLang := range targetLangs {
			if langSlug == targetLang {
				return snippetMap["code"].(string), nil
			}
		}
	}

	// If no exact match, return available languages
	availableLangs := []string{}
	for _, snippet := range codeSnippets {
		snippetMap := snippet.(map[string]interface{})
		availableLangs = append(availableLangs, snippetMap["langSlug"].(string))
	}

	return "", fmt.Errorf("language '%s' not available for problem %s. Available languages: %s",
		language, titleSlug, strings.Join(availableLangs, ", "))
}

func (c *LeetCodeGraphQLClient) GetQuestionID(ctx context.Context, titleSlug string) (string, error) {
	query := `
		query questionData($titleSlug: String!) {
			question(titleSlug: $titleSlug) {
				questionId
			}
		}`
	variables := map[string]interface{}{"titleSlug": titleSlug}
	resp := make(map[string]interface{})
	if err := c.postGraphQL(ctx, query, variables, &resp); err != nil {
		return "", err
	}

	question := resp["data"].(map[string]interface{})["question"].(map[string]interface{})
	questionID, ok := question["questionId"].(string)
	if !ok {
		return "", fmt.Errorf("could not get question ID for problem %s", titleSlug)
	}
	return questionID, nil
}

func (c *LeetCodeGraphQLClient) GetContestProblems(ctx context.Context, contestSlug string) ([]map[string]interface{}, error) {
	query := `
		query getContestProblems($titleSlug: String!) {
			contest(titleSlug: $titleSlug) {
				questions {
					title
					titleSlug
				}
			}
		}`
	variables := map[string]interface{}{"titleSlug": contestSlug}
	resp := make(map[string]interface{})
	if err := c.postGraphQL(ctx, query, variables, &resp); err != nil {
		return nil, err
	}
	questions := resp["data"].(map[string]interface{})["contest"].(map[string]interface{})["questions"].([]interface{})
	result := []map[string]interface{}{}
	for _, q := range questions {
		result = append(result, q.(map[string]interface{}))
	}
	return result, nil
}

func (c *LeetCodeGraphQLClient) SubmitSolution(ctx context.Context, titleSlug, lang, code string) (map[string]interface{}, error) {
	// Refresh CSRF token first
	if err := c.RefreshCSRFToken(ctx); err != nil {
		log.Printf("Warning: Could not refresh CSRF token: %v", err)
	}

	// First get the question ID
	questionID, err := c.GetQuestionID(ctx, titleSlug)
	if err != nil {
		return nil, fmt.Errorf("failed to get question ID: %v", err)
	}

	// Submit solution using REST endpoint
	url := fmt.Sprintf("https://leetcode.com/problems/%s/submit/", titleSlug)
	payload := map[string]interface{}{
		"lang":        lang,
		"question_id": questionID,
		"typed_code":  code,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}

	// Set all required headers exactly as in working bash script
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRFToken", c.csrfToken)
	req.Header.Set("Origin", "https://leetcode.com")
	req.Header.Set("Referer", fmt.Sprintf("https://leetcode.com/problems/%s/", titleSlug))
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Sec-Ch-Ua", `"Not)A;Brand";v="8", "Chromium";v="138", "Brave";v="138"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Gpc", "1")
	req.Header.Set("Priority", "u=1, i")
	req.Header.Set("Cookie", fmt.Sprintf("LEETCODE_SESSION=%s; csrftoken=%s", c.sessionID, c.csrfToken))

	log.Printf("Submitting to URL: %s", url)
	log.Printf("Payload: %s", string(b))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Printf("Response Status: %d", resp.StatusCode)

	if resp.StatusCode == 403 {
		// Try refreshing CSRF token and retry
		if err := c.RefreshCSRFToken(ctx); err != nil {
			return nil, fmt.Errorf("CSRF verification failed and could not refresh token: %v", err)
		}

		// Retry with new token
		req.Header.Set("X-CSRFToken", c.csrfToken)
		req.Header.Set("Cookie", fmt.Sprintf("LEETCODE_SESSION=%s; csrftoken=%s", c.sessionID, c.csrfToken))

		resp, err = c.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("submission failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse submission response
	var submissionResp SubmissionResponse
	if err := json.Unmarshal(body, &submissionResp); err != nil {
		return nil, fmt.Errorf("failed to parse submission response: %v, body: %s", err, string(body))
	}

	if submissionResp.SubmissionID == 0 {
		return nil, fmt.Errorf("no submission ID received, response: %s", string(body))
	}

	// Convert to string for consistency
	submissionIDStr := strconv.FormatInt(submissionResp.SubmissionID, 10)

	// Wait a bit for processing
	time.Sleep(3 * time.Second)

	// Check submission status
	status, err := c.CheckSubmissionStatus(ctx, submissionIDStr)
	if err != nil {
		return map[string]interface{}{
			"submission_id": submissionIDStr,
			"status":        "submitted",
			"message":       "Submission successful, but status check failed: " + err.Error(),
			"url":           fmt.Sprintf("https://leetcode.com/submissions/detail/%s/", submissionIDStr),
		}, nil
	}

	result := map[string]interface{}{
		"submission_id":   submissionIDStr,
		"status":          status.StatusMsg,
		"runtime":         status.StatusRuntime,
		"memory":          status.StatusMemory,
		"total_correct":   status.TotalCorrect,
		"total_testcases": status.TotalTestcases,
		"url":             fmt.Sprintf("https://leetcode.com/submissions/detail/%s/", submissionIDStr),
		"finished":        status.Finished,
	}

	// Add error details if any
	if status.RuntimeError != "" {
		result["runtime_error"] = status.RuntimeError
	}
	if status.FullRuntimeError != "" {
		result["full_runtime_error"] = status.FullRuntimeError
	}
	if status.CompileError != "" {
		result["compile_error"] = status.CompileError
	}
	if status.LastTestcase != "" {
		result["last_testcase"] = status.LastTestcase
		result["expected_output"] = status.ExpectedOutput
		result["code_output"] = status.CodeOutput
	}

	return result, nil
}

func (c *LeetCodeGraphQLClient) CheckSubmissionStatus(ctx context.Context, submissionID string) (*SubmissionStatusResponse, error) {
	url := fmt.Sprintf("https://leetcode.com/submissions/detail/%s/check/", submissionID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Cookie", fmt.Sprintf("LEETCODE_SESSION=%s; csrftoken=%s", c.sessionID, c.csrfToken))
	req.Header.Set("X-CSRFToken", c.csrfToken)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Referer", fmt.Sprintf("https://leetcode.com/submissions/detail/%s/", submissionID))
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == 403 {
		// Try refreshing CSRF token and retry
		if err := c.RefreshCSRFToken(ctx); err != nil {
			return nil, fmt.Errorf("CSRF verification failed and could not refresh token: %v", err)
		}

		// Retry with new token
		req.Header.Set("X-CSRFToken", c.csrfToken)
		req.Header.Set("Cookie", fmt.Sprintf("LEETCODE_SESSION=%s; csrftoken=%s", c.sessionID, c.csrfToken))

		resp, err = c.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("status check failed with status %d: %s", resp.StatusCode, string(body))
	}

	var status SubmissionStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %v", err)
	}

	return &status, nil
}

func (c *LeetCodeGraphQLClient) postGraphQL(ctx context.Context, query string, variables map[string]interface{}, out interface{}) error {
	payload := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://leetcode.com/graphql", bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRFToken", c.csrfToken)
	req.Header.Set("Referer", "https://leetcode.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Cookie", fmt.Sprintf("LEETCODE_SESSION=%s; csrftoken=%s", c.sessionID, c.csrfToken))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GraphQL request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func cleanHTML(content string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	cleaned := re.ReplaceAllString(content, "")

	// Replace HTML entities
	cleaned = strings.ReplaceAll(cleaned, "&nbsp;", " ")
	cleaned = strings.ReplaceAll(cleaned, "&lt;", "<")
	cleaned = strings.ReplaceAll(cleaned, "&gt;", ">")
	cleaned = strings.ReplaceAll(cleaned, "&amp;", "&")
	cleaned = strings.ReplaceAll(cleaned, "&quot;", "\"")

	return strings.TrimSpace(cleaned)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	log.SetOutput(os.Stderr)
	session := os.Getenv("LEETCODE_SESSION")
	csrf := os.Getenv("LEETCODE_CSRF_TOKEN")

	if session == "" {
		log.Fatal("Please set LEETCODE_SESSION environment variable")
	}

	client := NewLeetCodeGraphQLClient(&AuthConfig{session, csrf})

	s := server.NewMCPServer("leetcode-mcp", "1.0.0")

	s.AddTool(mcp.NewTool("list_problems",
		mcp.WithDescription("List LeetCode problems"),
		mcp.WithNumber("limit", mcp.Required()),
		mcp.WithNumber("skip")), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		limit, _ := req.RequireFloat("limit")
		skip := req.GetFloat("skip", 0)
		list, err := client.GetProblemList(ctx, int(limit), int(skip))
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, _ := json.MarshalIndent(list, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("get_problem",
		mcp.WithDescription("Get problem details including description and code templates"),
		mcp.WithString("title_slug", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		slug, _ := req.RequireString("title_slug")
		problem, err := client.GetProblem(ctx, slug)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Clean up the content field if it exists
		if content, exists := problem["content"].(string); exists {
			problem["content"] = cleanHTML(content)
		}

		b, _ := json.MarshalIndent(problem, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("get_problem_stub",
		mcp.WithDescription("Get the code template/stub for a specific problem and language"),
		mcp.WithString("title_slug", mcp.Required()),
		mcp.WithString("language", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		slug, _ := req.RequireString("title_slug")
		language, _ := req.RequireString("language")

		stub, err := client.GetProblemStub(ctx, slug, language)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		result := map[string]interface{}{
			"title_slug": slug,
			"language":   language,
			"code_stub":  stub,
		}

		b, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("submit_solution",
		mcp.WithDescription("Submit solution to LeetCode and get detailed results"),
		mcp.WithString("title_slug", mcp.Required()),
		mcp.WithString("lang", mcp.Required()),
		mcp.WithString("code", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		slug, _ := req.RequireString("title_slug")
		lang, _ := req.RequireString("lang")
		code, _ := req.RequireString("code")

		result, err := client.SubmitSolution(ctx, slug, lang, code)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		b, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("check_submission_status",
		mcp.WithDescription("Check the status of a LeetCode submission"),
		mcp.WithString("submission_id", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		submissionID, _ := req.RequireString("submission_id")

		status, err := client.CheckSubmissionStatus(ctx, submissionID)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		b, _ := json.MarshalIndent(status, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("get_contest_problems",
		mcp.WithDescription("Get all problems from a LeetCode contest"),
		mcp.WithString("contest_slug", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		slug, _ := req.RequireString("contest_slug")
		problems, err := client.GetContestProblems(ctx, slug)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, _ := json.MarshalIndent(problems, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("filter_contest_problems_by_tag",
		mcp.WithDescription("Filter contest problems by tag"),
		mcp.WithString("contest_slug", mcp.Required()),
		mcp.WithString("tag", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		contestSlug, _ := req.RequireString("contest_slug")
		tag, _ := req.RequireString("tag")
		problems, err := client.GetContestProblems(ctx, contestSlug)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		filtered := []map[string]interface{}{}
		for _, p := range problems {
			details, err := client.GetProblem(ctx, p["titleSlug"].(string))
			if err != nil {
				continue
			}
			tags := details["topicTags"].([]interface{})
			for _, t := range tags {
				if strings.EqualFold(t.(map[string]interface{})["name"].(string), tag) {
					filtered = append(filtered, details)
					break
				}
			}
		}
		b, _ := json.MarshalIndent(filtered, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("get_tags_from_contest",
		mcp.WithDescription("Get all tags used in a given contest's problems"),
		mcp.WithString("contest_slug", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		slug, _ := req.RequireString("contest_slug")
		problems, err := client.GetContestProblems(ctx, slug)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		tagSet := map[string]bool{}
		for _, p := range problems {
			details, err := client.GetProblem(ctx, p["titleSlug"].(string))
			if err != nil {
				continue
			}
			tags := details["topicTags"].([]interface{})
			for _, t := range tags {
				tagSet[t.(map[string]interface{})["name"].(string)] = true
			}
		}
		tagList := []string{}
		for tag := range tagSet {
			tagList = append(tagList, tag)
		}
		b, _ := json.MarshalIndent(tagList, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
