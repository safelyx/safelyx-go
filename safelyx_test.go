package safelyx_test

import (
	"os"
	"testing"

	"github.com/safelyx/safelyx-go"
)

func TestCheckLink(t *testing.T) {
	keyCode := os.Getenv("TEST_KEY_CODE")
	client := safelyx.NewClient(keyCode)

	tests := []struct {
		url      string
		expected struct {
			URL        string
			Result     int
			ResultText string
			Date       string
			Analysis   struct {
				DomainReputation string
				SourceCode       string
				AntiVirus        string
			}
			ChecksRemaining int
		}
	}{
		{
			url: "example.com",
			expected: struct {
				URL        string
				Result     int
				ResultText string
				Date       string
				Analysis   struct {
					DomainReputation string
					SourceCode       string
					AntiVirus        string
				}
				ChecksRemaining int
			}{
				URL:        "https://example.com",
				Result:     8,
				ResultText: "This link looks safe.",
				Date:       "2025-01-01",
				Analysis: struct {
					DomainReputation string
					SourceCode       string
					AntiVirus        string
				}{
					DomainReputation: "This domain wasn't found in any malicious lists.",
					SourceCode:       "This website appears to have basic HTML.",
					AntiVirus:        "N/A",
				},
				ChecksRemaining: 1000,
			},
		},
	}

	for _, test := range tests {
		result, err := client.CheckLink(test.url)
		if err != nil {
			t.Errorf("CheckLink failed: %v", err)
		}

		if result.URL != "https://example.com" {
			t.Errorf("Expected URL to be https://example.com, got %s", result.URL)
		}

		if result.Result != -2 && (result.Result < 8 || result.Result > 10) {
			t.Errorf("Expected result to be -2 or between 8 and 10, got %d", result.Result)
		}

		if result.ResultText == "" {
			t.Error("Expected result_text to be present")
		}
		if result.Date == "" {
			t.Error("Expected date to be present")
		}
		if result.Analysis.DomainReputation == "" {
			t.Error("Expected domain_reputation to be present in analysis")
		}
		if result.Analysis.SourceCode == "" {
			t.Error("Expected source_code to be present in analysis")
		}
		if result.Analysis.AntiVirus == "" {
			t.Error("Expected anti_virus to be present in analysis")
		}
		if result.ChecksRemaining < 0 {
			t.Error("Expected checks_remaining to be present")
		}
	}
}

func TestCheckEmail(t *testing.T) {
	keyCode := os.Getenv("TEST_KEY_CODE")
	client := safelyx.NewClient(keyCode)

	tests := []struct {
		email    string
		expected struct {
			Email      string
			Result     int
			ResultText string
			Date       string
			Analysis   struct {
				Address          string
				DomainReputation string
				MXRecords        string
			}
			ChecksRemaining int
		}
	}{
		{
			email: "help@safelyx.com",
			expected: struct {
				Email      string
				Result     int
				ResultText string
				Date       string
				Analysis   struct {
					Address          string
					DomainReputation string
					MXRecords        string
				}
				ChecksRemaining int
			}{
				Email:      "help@safelyx.com",
				Result:     8,
				ResultText: "This email looks legitimate.",
				Date:       "2025-01-01",
				Analysis: struct {
					Address          string
					DomainReputation string
					MXRecords        string
				}{
					Address:          "This email address is valid.",
					DomainReputation: "This domain isn't found in any malicious lists.",
					MXRecords:        "This domain has valid MX records.",
				},
				ChecksRemaining: 1000,
			},
		},
	}

	for _, test := range tests {
		result, err := client.CheckEmail(test.email)
		if err != nil {
			t.Errorf("CheckEmail failed: %v", err)
		}

		if result.Email != test.email {
			t.Errorf("Expected email to be %s, got %s", test.email, result.Email)
		}

		if result.Result != -2 && (result.Result < 8 || result.Result > 10) {
			t.Errorf("Expected result to be -2 or between 8 and 10, got %d", result.Result)
		}

		if result.ResultText == "" {
			t.Error("Expected result_text to be present")
		}
		if result.Date == "" {
			t.Error("Expected date to be present")
		}
		if result.Analysis.Address == "" {
			t.Error("Expected address to be present in analysis")
		}
		if result.Analysis.DomainReputation == "" {
			t.Error("Expected domain_reputation to be present in analysis")
		}
		if result.Analysis.MXRecords == "" {
			t.Error("Expected mx_records to be present in analysis")
		}
		if result.ChecksRemaining < 0 {
			t.Error("Expected checks_remaining to be present")
		}
	}
}

func TestCheckMessage(t *testing.T) {
	keyCode := os.Getenv("TEST_KEY_CODE")
	client := safelyx.NewClient(keyCode)

	tests := []struct {
		message  string
		expected struct {
			Message    string
			Result     int
			ResultText string
			Date       string
			Analysis   struct {
				Content   string
				Sentiment string
				Links     []string
				Emails    []string
			}
			ChecksRemaining int
		}
	}{
		{
			message: "Hello, world!",
			expected: struct {
				Message    string
				Result     int
				ResultText string
				Date       string
				Analysis   struct {
					Content   string
					Sentiment string
					Links     []string
					Emails    []string
				}
				ChecksRemaining int
			}{
				Message:    "Hello, world!",
				Result:     8,
				ResultText: "This message appears to be safe.",
				Date:       "2025-01-01",
				Analysis: struct {
					Content   string
					Sentiment string
					Links     []string
					Emails    []string
				}{
					Content:   "This message appears to be safe.",
					Sentiment: "positive",
					Links:     []string{},
					Emails:    []string{},
				},
				ChecksRemaining: 1000,
			},
		},
	}

	for _, test := range tests {
		result, err := client.CheckMessage(test.message, false)
		if err != nil {
			t.Errorf("CheckMessage failed: %v", err)
		}

		if result.Message != test.expected.Message {
			t.Errorf("Expected message to be %s, got %s", test.expected.Message, result.Message)
		}

		if result.Result != -2 && (result.Result < 8 || result.Result > 10) {
			t.Errorf("Expected result to be -2 or between 8 and 10, got %d", result.Result)
		}

		if result.ResultText == "" {
			t.Error("Expected result_text to be present")
		}
		if result.Date == "" {
			t.Error("Expected date to be present")
		}
		if result.Analysis.Content == "" {
			t.Error("Expected content to be present in analysis")
		}
		if result.Analysis.Sentiment == "" {
			t.Error("Expected sentiment to be present in analysis")
		}
		if result.ChecksRemaining < 0 {
			t.Error("Expected checks_remaining to be present")
		}
	}
}

func TestCheckImage(t *testing.T) {
	keyCode := os.Getenv("TEST_KEY_CODE")
	client := safelyx.NewClient(keyCode)

	tests := []struct {
		imageURL string
		expected struct {
			ImageURL   string
			Result     int
			ResultText string
			Date       string
			Analysis   struct {
				Description string
				Link        struct {
					URL      string
					Result   int
					Date     string
					Analysis struct {
						DomainReputation string
						SourceCode       string
						AntiVirus        string
					}
				}
			}
			ChecksRemaining int
		}
	}{
		{
			imageURL: "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
			expected: struct {
				ImageURL   string
				Result     int
				ResultText string
				Date       string
				Analysis   struct {
					Description string
					Link        struct {
						URL      string
						Result   int
						Date     string
						Analysis struct {
							DomainReputation string
							SourceCode       string
							AntiVirus        string
						}
					}
				}
				ChecksRemaining int
			}{
				ImageURL:   "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
				Result:     8,
				ResultText: "This image appears to be safe.",
				Date:       "2025-01-01",
				Analysis: struct {
					Description string
					Link        struct {
						URL      string
						Result   int
						Date     string
						Analysis struct {
							DomainReputation string
							SourceCode       string
							AntiVirus        string
						}
					}
				}{
					Description: "This image appears to be safe.",
					Link: struct {
						URL      string
						Result   int
						Date     string
						Analysis struct {
							DomainReputation string
							SourceCode       string
							AntiVirus        string
						}
					}{
						URL:    "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png",
						Result: 8,
						Date:   "2025-01-01",
						Analysis: struct {
							DomainReputation string
							SourceCode       string
							AntiVirus        string
						}{
							DomainReputation: "This domain wasn't found in any malicious lists.",
							SourceCode:       "This link returns a file.",
							AntiVirus:        "No viruses found.",
						},
					},
				},
				ChecksRemaining: 1000,
			},
		},
	}

	for _, test := range tests {
		result, err := client.CheckImage(test.imageURL)
		if err != nil {
			t.Errorf("CheckImage failed: %v", err)
		}

		if result.ImageURL != test.expected.ImageURL {
			t.Errorf("Expected image_url to be %s, got %s", test.expected.ImageURL, result.ImageURL)
		}

		if result.Result != -2 && (result.Result < 8 || result.Result > 10) {
			t.Errorf("Expected result to be -2 or between 8 and 10, got %d", result.Result)
		}

		if result.ResultText == "" {
			t.Error("Expected result_text to be present")
		}
		if result.Date == "" {
			t.Error("Expected date to be present")
		}
		if result.Analysis.Description == "" {
			t.Error("Expected description to be present in analysis")
		}
		if result.Analysis.Link.URL == "" {
			t.Error("Expected url to be present in analysis.link")
		}
		if result.Analysis.Link.Result < -1 {
			t.Error("Expected result to be present in analysis.link")
		}
		if result.Analysis.Link.Date == "" {
			t.Error("Expected date to be present in analysis.link")
		}
		if result.Analysis.Link.Analysis.DomainReputation == "" {
			t.Error("Expected domain_reputation to be present in analysis.link.analysis")
		}
		if result.Analysis.Link.Analysis.SourceCode == "" {
			t.Error("Expected source_code to be present in analysis.link.analysis")
		}
		if result.Analysis.Link.Analysis.AntiVirus == "" {
			t.Error("Expected anti_virus to be present in analysis.link.analysis")
		}
		if result.ChecksRemaining < 0 {
			t.Error("Expected checks_remaining to be present")
		}
	}
}
