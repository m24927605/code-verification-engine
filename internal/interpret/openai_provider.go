package interpret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OpenAIProvider sends prompts to an OpenAI-compatible API endpoint
// (OpenAI, Azure OpenAI, or any OpenAI-compatible service).
type OpenAIProvider struct {
	apiKey           string
	apiURL           string
	model            string
	client           *http.Client
	MaxResponseBytes int64 // 0 = use default (65536)
}

// NewOpenAIProvider creates a provider that calls an OpenAI-compatible chat completions endpoint.
// If model is empty, defaults to "o3-mini".
func NewOpenAIProvider(apiKey, apiURL, model string) *OpenAIProvider {
	if model == "" {
		model = "o3-mini"
	}
	return &OpenAIProvider{
		apiKey:           apiKey,
		apiURL:           apiURL,
		model:            model,
		client:           &http.Client{},
		MaxResponseBytes: 65536,
	}
}

func (p *OpenAIProvider) Complete(ctx context.Context, prompt string) (string, error) {
	body := map[string]interface{}{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	maxBytes := p.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 65536
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if int64(len(respBody)) > maxBytes {
		return "", ErrResponseTooLarge
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", nil
	}
	return result.Choices[0].Message.Content, nil
}
