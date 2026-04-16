package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHasModelMatchesLatestAlias(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{"name": "llama3.2:latest"},
			},
		})
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL, "llama3.2")
	ok, err := client.HasModel(context.Background())
	if err != nil {
		t.Fatalf("HasModel returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected model to match latest alias")
	}
}

func TestGenerateUsesNonStreamingRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("could not decode request: %v", err)
		}
		if request["model"] != "llama3.2:1b" {
			t.Fatalf("unexpected model: %v", request["model"])
		}
		if request["stream"] != false {
			t.Fatalf("expected stream=false, got %v", request["stream"])
		}

		_ = json.NewEncoder(w).Encode(map[string]string{
			"response": "analysis ready",
		})
	}))
	defer server.Close()

	client := NewOllamaClient(server.URL+"/", "llama3.2:1b")
	got, err := client.Generate(context.Background(), "summarize")
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if got != "analysis ready" {
		t.Fatalf("unexpected response: %q", got)
	}
}
