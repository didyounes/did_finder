package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SendDiscordWebhook sends scan results to a Discord channel
func SendDiscordWebhook(webhookURL, domain string, subdomainCount int, takeoverCount int) error {
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "🔍 did_finder Scan Complete",
				"description": fmt.Sprintf("Scan for **%s** has completed.", domain),
				"color":       3447003,
				"fields": []map[string]interface{}{
					{"name": "Subdomains Found", "value": fmt.Sprintf("%d", subdomainCount), "inline": true},
					{"name": "Takeover Vulns", "value": fmt.Sprintf("%d", takeoverCount), "inline": true},
				},
				"footer": map[string]string{
					"text": "did_finder v3.0",
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}

	data, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

// SendSlackWebhook sends scan results to a Slack channel
func SendSlackWebhook(webhookURL, domain string, subdomainCount int, takeoverCount int) error {
	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": "🔍 did_finder Scan Complete",
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Domain:*\n%s", domain)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Subdomains:*\n%d", subdomainCount)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Takeover Vulns:*\n%d", takeoverCount)},
				},
			},
		},
	}

	data, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
