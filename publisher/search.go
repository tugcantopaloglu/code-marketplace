package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/code-marketplace/storage"
)

const SearchPageSize = 20

type SearchEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Publisher   string `json:"publisher"`
	Verified    bool   `json:"verified"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type SearchResult struct {
	Entries []SearchEntry `json:"entries"`
	Page    int           `json:"page"`
	HasMore bool          `json:"hasMore"`
}

// Search returns public identity data. Version is a gallery search hint, not a
// pinned release; Collect independently resolves the latest stable target build.
func Search(ctx context.Context, client *http.Client, text string, page int) (*SearchResult, error) {
	text = strings.TrimSpace(text)
	if len(text) < 2 || len(text) > 200 || page < 1 || page > 100 {
		return nil, fmt.Errorf("arama 2–200 karakter, sayfa 1–100 arasında olmalı")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *client
	if safe.Timeout == 0 {
		safe.Timeout = 30 * time.Second
	}
	safe.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 10 || !trustedURL(r.URL) {
			return fmt.Errorf("untrusted Marketplace redirect")
		}
		return nil
	}
	// IncludeLatestVersionOnly (512) + IncludeVersionProperties (16).
	// Search must not fetch every version's assets for twenty extensions.
	body, _ := json.Marshal(map[string]any{
		"filters": []any{map[string]any{"criteria": []any{
			map[string]any{"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
			map[string]any{"filterType": 10, "value": text},
		}, "pageNumber": page, "pageSize": SearchPageSize}}, "flags": 528,
	})
	data, err := fetch(ctx, &safe, http.MethodPost, Marketplace+"/_apis/public/gallery/extensionquery", body, 8<<20)
	if err != nil {
		return nil, err
	}
	var response struct {
		Results []struct {
			Extensions []struct {
				Name        string           `json:"extensionName"`
				DisplayName string           `json:"displayName"`
				Description string           `json:"shortDescription"`
				Publisher   galleryPublisher `json:"publisher"`
				Versions    []galleryVersion `json:"versions"`
			} `json:"extensions"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, err
	}
	if len(response.Results) != 1 {
		return nil, fmt.Errorf("Marketplace arama yanıtı geçersiz")
	}
	result := &SearchResult{Entries: []SearchEntry{}, Page: page, HasMore: len(response.Results[0].Extensions) == SearchPageSize}
	for _, entry := range response.Results[0].Extensions {
		if storage.ValidateComponent(entry.Publisher.Name) != nil || storage.ValidateComponent(entry.Name) != nil {
			continue
		}
		name := entry.DisplayName
		if name == "" {
			name = entry.Name
		}
		version := ""
		if len(entry.Versions) > 0 {
			version = entry.Versions[0].Version.Version
		}
		result.Entries = append(result.Entries, SearchEntry{
			ID: entry.Publisher.Name + "." + entry.Name, Name: name, Publisher: entry.Publisher.DisplayName,
			Verified: entry.Publisher.Verified, Description: entry.Description, Version: version,
		})
	}
	return result, nil
}
