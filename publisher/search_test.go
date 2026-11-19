package publisher_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/coder/code-marketplace/publisher"
	"github.com/stretchr/testify/require"
)

func TestSearchPreservesPublisherIdentityAndBoundsMetadata(t *testing.T) {
	client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		require.Equal(t, http.MethodPost, r.Method)
		var query map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&query))
		require.Equal(t, float64(528), query["flags"])
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"results":[{"extensions":[{"extensionName":"python","displayName":"Python","publisher":{"publisherName":"ms-python","displayName":"Microsoft","isDomainVerified":true},"versions":[{"version":"2026.10.0"}]},{"extensionName":"../bad","publisher":{"publisherName":"impostor"}}]}]}`)), Request: r}, nil
	})}
	result, err := publisher.Search(context.Background(), client, "python", 1)
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	require.Equal(t, "ms-python.python", result.Entries[0].ID)
	require.True(t, result.Entries[0].Verified)
	_, err = publisher.Search(context.Background(), client, "", 1)
	require.Error(t, err)
	_, err = publisher.Search(context.Background(), client, "python", 101)
	require.Error(t, err)
}
