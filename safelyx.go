package safelyx

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// SafeLinkResponse represents the response from the CheckLink function
type SafeLinkResponse struct {
	URL             string       `json:"url"`
	Result          int          `json:"result"`
	ResultText      string       `json:"result_text"`
	Date            string       `json:"date"`
	Analysis        LinkAnalysis `json:"analysis"`
	ChecksRemaining int          `json:"checks_remaining"`
}

type LinkAnalysis struct {
	DomainReputation string `json:"domain_reputation"`
	SourceCode       string `json:"source_code"`
	AntiVirus        string `json:"anti_virus"`
}

// SafeEmailResponse represents the response from the CheckEmail function
type SafeEmailResponse struct {
	Email           string        `json:"email"`
	Result          int           `json:"result"`
	ResultText      string        `json:"result_text"`
	Date            string        `json:"date"`
	Analysis        EmailAnalysis `json:"analysis"`
	ChecksRemaining int           `json:"checks_remaining"`
}

type EmailAnalysis struct {
	Address          string `json:"address"`
	DomainReputation string `json:"domain_reputation"`
	MXRecords        string `json:"mx_records"`
}

// SafeMessageResponse represents the response from the CheckMessage function
type SafeMessageResponse struct {
	Message         string          `json:"message"`
	Result          int             `json:"result"`
	ResultText      string          `json:"result_text"`
	Date            string          `json:"date"`
	Analysis        MessageAnalysis `json:"analysis"`
	ChecksRemaining int             `json:"checks_remaining"`
}

type MessageAnalysis struct {
	Content   string                    `json:"content"`
	Sentiment string                    `json:"sentiment"`
	Links     []SimplifiedLinkResponse  `json:"links"`
	Emails    []SimplifiedEmailResponse `json:"emails"`
}

type SimplifiedLinkResponse struct {
	URL      string       `json:"url"`
	Result   int          `json:"result"`
	Date     string       `json:"date"`
	Analysis LinkAnalysis `json:"analysis"`
}

type SimplifiedEmailResponse struct {
	Email    string        `json:"email"`
	Result   int           `json:"result"`
	Date     string        `json:"date"`
	Analysis EmailAnalysis `json:"analysis"`
}

// SafeImageResponse represents the response from the CheckImage function
type SafeImageResponse struct {
	ImageURL        string        `json:"image_url"`
	Result          int           `json:"result"`
	ResultText      string        `json:"result_text"`
	Date            string        `json:"date"`
	Analysis        ImageAnalysis `json:"analysis"`
	ChecksRemaining int           `json:"checks_remaining"`
}

type ImageAnalysis struct {
	Description string                 `json:"description"`
	Link        SimplifiedLinkResponse `json:"link"`
}

// Client represents a Safelyx API client
type Client struct {
	httpClient *http.Client
	keyCode    string
}

// NewClient creates a new Safelyx API client
func NewClient(keyCode string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		keyCode: keyCode,
	}
}

// CheckLink securely checks if a link is safe to click or visit
func (c *Client) CheckLink(link string) (*SafeLinkResponse, error) {
	payload := map[string]interface{}{
		"link":     link,
		"key_code": c.keyCode,
	}

	resp, err := c.makeRequest("https://safelyx.com/safe-link-checker", payload)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result SafeLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CheckEmail securely checks if an email address is legitimate
func (c *Client) CheckEmail(email string) (*SafeEmailResponse, error) {
	payload := map[string]interface{}{
		"email":    email,
		"key_code": c.keyCode,
	}

	resp, err := c.makeRequest("https://safelyx.com/safe-email-checker", payload)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result SafeEmailResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CheckMessage securely checks if a message's content is safe
func (c *Client) CheckMessage(message string, skipLinkAndEmailChecks bool) (*SafeMessageResponse, error) {
	payload := map[string]interface{}{
		"message":                    message,
		"skip_link_and_email_checks": skipLinkAndEmailChecks,
		"key_code":                   c.keyCode,
	}

	resp, err := c.makeRequest("https://safelyx.com/safe-message-checker", payload)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result SafeMessageResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// CheckImage securely checks if an image is safe
func (c *Client) CheckImage(imageURL string) (*SafeImageResponse, error) {
	payload := map[string]interface{}{
		"image_url": imageURL,
		"key_code":  c.keyCode,
	}

	resp, err := c.makeRequest("https://safelyx.com/safe-image-checker", payload)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result SafeImageResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) makeRequest(url string, payload interface{}) (*http.Response, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")

	return c.httpClient.Do(req)
}
