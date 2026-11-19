package publisher

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrustedMarketplaceAssetURLs(t *testing.T) {
	for _, address := range []string{"http://marketplace.visualstudio.com/x", "https://127.0.0.1/x", "https://marketplace.visualstudio.com.attacker.test/x", "https://vsassets.io.attacker.test/x", "https://user@marketplace.visualstudio.com/x", "https://marketplace.visualstudio.com:8443/x", "https://cdn.vsassets.io:123/x", "https://marketplace.visualstudio.com/x#fragment"} {
		u, err := url.Parse(address)
		require.NoError(t, err)
		require.False(t, trustedURL(u), address)
	}
	for _, address := range []string{"https://marketplace.visualstudio.com/x", "https://publisher.gallery.vsassets.io/x", "https://marketplace.visualstudio.com:443/x"} {
		u, err := url.Parse(address)
		require.NoError(t, err)
		require.True(t, trustedURL(u), address)
	}
}
