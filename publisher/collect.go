package publisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/code-marketplace/extensionsign"
	"github.com/coder/code-marketplace/storage"
	"golang.org/x/mod/semver"
)

type CollectOptions struct {
	Extension  string
	Version    string
	Platform   storage.Platform
	KeyID      string
	Key        ed25519.PrivateKey
	Validity   time.Duration
	Client     *http.Client
	PreRelease bool
}

type Bundle struct {
	Manifest  *storage.VSIXManifest
	VSIX      []byte
	Signature []byte
	Report    []byte
	Claims    Claims
}

type galleryPublisher struct {
	ID          string `json:"publisherId"`
	Name        string `json:"publisherName"`
	DisplayName string `json:"displayName"`
	Domain      string `json:"domain"`
	Verified    bool   `json:"isDomainVerified"`
}

type galleryVersion struct {
	storage.Version
	Files []struct {
		Type   string `json:"assetType"`
		Source string `json:"source"`
	} `json:"files"`
	Properties []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"properties"`
}

func Collect(ctx context.Context, options CollectOptions) (*Bundle, error) {
	name, extension, ok := strings.Cut(options.Extension, ".")
	if !ok || storage.ValidateComponent(name) != nil || storage.ValidateComponent(extension) != nil || options.Validity <= 0 || options.Validity > 30*24*time.Hour || options.KeyID == "" || len(options.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("valid extension ID, collector signing key, and report validity up to 30 days are required")
	}
	if err := storage.ValidateIdentity(name, extension, storage.Version{Version: "1.0.0", TargetPlatform: options.Platform}); err != nil {
		return nil, err
	}
	client := options.Client
	if client == nil {
		client = &http.Client{}
	}
	safeClient := *client
	if safeClient.Timeout <= 0 {
		safeClient.Timeout = 2 * time.Minute
	}
	previousRedirect := safeClient.CheckRedirect
	safeClient.CheckRedirect = func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 10 || !trustedURL(request.URL) {
			return fmt.Errorf("untrusted Marketplace asset redirect")
		}
		if previousRedirect != nil {
			return previousRedirect(request, previous)
		}
		return nil
	}
	client = &safeClient
	query, err := json.Marshal(map[string]any{"filters": []any{map[string]any{"criteria": []any{map[string]any{"filterType": 7, "value": options.Extension}}, "pageSize": 1}}, "flags": 19})
	if err != nil {
		return nil, err
	}
	metadata, err := fetch(ctx, client, http.MethodPost, Marketplace+"/_apis/public/gallery/extensionquery", query, 16<<20)
	if err != nil {
		return nil, err
	}
	var response struct {
		Results []struct {
			Extensions []struct {
				Name      string           `json:"extensionName"`
				Publisher galleryPublisher `json:"publisher"`
				Versions  []galleryVersion `json:"versions"`
			} `json:"extensions"`
		} `json:"results"`
	}
	if err := json.Unmarshal(metadata, &response); err != nil {
		return nil, err
	}
	if len(response.Results) != 1 || len(response.Results[0].Extensions) != 1 {
		return nil, fmt.Errorf("marketplace did not return exactly one extension")
	}
	entry := response.Results[0].Extensions[0]
	if !strings.EqualFold(entry.Name, extension) || !strings.EqualFold(entry.Publisher.Name, name) {
		return nil, fmt.Errorf("marketplace returned a different extension or publisher")
	}
	var selected *galleryVersion
	for i := range entry.Versions {
		version := &entry.Versions[i]
		if options.Version != "" && version.Version.Version != options.Version {
			continue
		}
		if options.Version == "" && !options.PreRelease {
			preview := false
			for _, property := range version.Properties {
				if property.Key == "Microsoft.VisualStudio.Code.PreRelease" && property.Value == "true" {
					preview = true
				}
			}
			if preview {
				continue
			}
		}
		if !version.CompatibleWith(options.Platform) {
			continue
		}
		if selected == nil || semver.Compare("v"+version.Version.Version, "v"+selected.Version.Version) > 0 || (version.Version.Version == selected.Version.Version && version.TargetPlatform == options.Platform) {
			selected = version
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("marketplace has no matching package version and platform")
	}
	if err := storage.ValidateIdentity(entry.Publisher.Name, entry.Name, selected.Version); err != nil {
		return nil, err
	}
	observedAt := time.Now().UTC()
	assets := map[string]string{}
	for _, file := range selected.Files {
		if file.Type != string(storage.VSIXAssetType) && file.Type != string(storage.VSIXSignatureType) {
			continue
		}
		if assets[file.Type] != "" {
			return nil, fmt.Errorf("marketplace returned duplicate package assets")
		}
		assets[file.Type] = file.Source
	}
	vsix, err := fetch(ctx, client, http.MethodGet, assets[string(storage.VSIXAssetType)], nil, storage.MaxPackageSize)
	if err != nil {
		return nil, err
	}
	signature, err := fetch(ctx, client, http.MethodGet, assets[string(storage.VSIXSignatureType)], nil, 34<<20)
	if err != nil {
		return nil, err
	}
	manifest, err := storage.ReadVSIXManifest(vsix)
	if err != nil {
		return nil, err
	}
	identity := manifest.Metadata.Identity
	version := storage.Version{Version: identity.Version, TargetPlatform: identity.TargetPlatform}
	if !strings.EqualFold(identity.Publisher, entry.Publisher.Name) || !strings.EqualFold(identity.ID, entry.Name) || version.String() != selected.String() {
		return nil, fmt.Errorf("downloaded VSIX does not match the Marketplace identity")
	}
	if err := storage.ValidatePackage(manifest, vsix); err != nil {
		return nil, err
	}
	if err := extensionsign.ValidateSignatureArchive(vsix, signature); err != nil {
		return nil, err
	}
	claims := Claims{SchemaVersion: 1, Source: Marketplace, Publisher: Identity{ID: entry.Publisher.ID, Name: entry.Publisher.Name, DisplayName: entry.Publisher.DisplayName, Domain: entry.Publisher.Domain, DomainVerified: entry.Publisher.Verified}, Extension: entry.Name, Version: version, SHA256: Hash(vsix), SignatureHash: Hash(signature), ObservedAt: observedAt, ExpiresAt: observedAt.Add(options.Validity)}
	report, err := Sign(claims, options.KeyID, options.Key)
	if err != nil {
		return nil, err
	}
	return &Bundle{Manifest: manifest, VSIX: vsix, Signature: signature, Report: report, Claims: claims}, nil
}

func (v galleryVersion) CompatibleWith(platform storage.Platform) bool {
	if v.TargetPlatform == platform {
		return true
	}
	switch v.TargetPlatform {
	case "", storage.PlatformUniversal, storage.PlatformUnknown, storage.PlatformUndefined:
		return true
	default:
		return false
	}
}

func fetch(ctx context.Context, client *http.Client, method, target string, body []byte, limit int64) ([]byte, error) {
	address, err := url.Parse(target)
	if err != nil || !trustedURL(address) {
		return nil, fmt.Errorf("untrusted Marketplace URL")
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json;api-version=7.2-preview.1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("marketplace request failed with status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("marketplace response exceeds size limit")
	}
	return data, nil
}

func trustedURL(address *url.URL) bool {
	if address == nil || address.Scheme != "https" || address.User != nil {
		return false
	}
	host := strings.ToLower(address.Hostname())
	return host == "marketplace.visualstudio.com" || strings.HasSuffix(host, ".vsassets.io")
}
