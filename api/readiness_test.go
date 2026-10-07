package api_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/api"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestStorageReadiness(t *testing.T) {
	for _, ready := range []bool{false, true} {
		server := api.New(&api.Options{Storage: testutil.NewMockStorage(), Logger: slog.Make(), Ready: func() error {
			if ready {
				return nil
			}
			return errors.New("unreadable storage")
		}})
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if ready {
			require.Equal(t, 200, response.Code)
		} else {
			require.Equal(t, 503, response.Code)
		}
		response = httptest.NewRecorder()
		server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		require.Equal(t, 200, response.Code)
	}
}
