package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type collectionConfig struct {
	TargetPlatform    storage.Platform  `yaml:"targetPlatform"`
	PublisherMode     string            `yaml:"publisherMode"`
	AllowedPublishers []string          `yaml:"allowedPublishers"`
	Extensions        []collectionEntry `yaml:"extensions"`
}

type collectionEntry struct {
	ID             string           `yaml:"id" json:"id"`
	Version        string           `yaml:"version,omitempty" json:"version,omitempty"`
	TargetPlatform storage.Platform `yaml:"targetPlatform,omitempty" json:"targetPlatform,omitempty"`
	PreRelease     bool             `yaml:"preRelease,omitempty" json:"preRelease,omitempty"`
}

type collectionResult struct {
	Request  collectionEntry   `json:"request"`
	Status   string            `json:"status"`
	Basename string            `json:"basename,omitempty"`
	Claims   *publisher.Claims `json:"claims,omitempty"`
	Error    string            `json:"error,omitempty"`
}

type collectionReport struct {
	SchemaVersion int                `json:"schemaVersion"`
	StartedAt     time.Time          `json:"startedAt"`
	FinishedAt    time.Time          `json:"finishedAt"`
	Collected     int                `json:"collected"`
	Reused        int                `json:"reused"`
	Failed        int                `json:"failed"`
	Results       []collectionResult `json:"results"`
}

func collectBatchCommand() *cobra.Command {
	var configPath, output, privateKeyPath string
	var attempts int
	options := publisher.CollectOptions{}
	cmd := &cobra.Command{Use: "collect-batch", Short: "Collect selected Marketplace extensions from a YAML list on a connected host", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if configPath == "" || output == "" || privateKeyPath == "" || options.KeyID == "" || len(options.KeyID) > 128 || options.Validity <= 0 || options.Validity > 30*24*time.Hour || attempts < 1 || attempts > 5 {
			return fmt.Errorf("--config, --output-dir, --signing-key, --key-id, validity up to 30 days, and 1 to 5 attempts are required")
		}
		config, err := loadCollectionConfig(configPath)
		if err != nil {
			return err
		}
		options.Key, err = readCollectorKey(privateKeyPath)
		if err != nil {
			return err
		}
		policy, err := config.policy(options)
		if err != nil {
			return err
		}
		root, err := openCollectorOutput(output)
		if err != nil {
			return err
		}
		defer root.Close()
		if err := root.Mkdir("incoming", 0o700); err != nil {
			return err
		}
		incoming, err := root.OpenRoot("incoming")
		if err != nil {
			return err
		}
		defer incoming.Close()
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stop()
		report := runCollectionBatch(ctx, config.Extensions, options, policy, incoming, attempts, publisher.Collect, cmd.ErrOrStderr())
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if err := writeCollectionReport(root, append(data, '\n')); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Collected: %d, reused: %d, failed: %d. Report: %s/batch-report.json\n", report.Collected, report.Reused, report.Failed, output); err != nil {
			return err
		}
		if report.Failed > 0 {
			return fmt.Errorf("%d extensions could not be collected; see batch-report.json", report.Failed)
		}
		return nil
	}}
	cmd.Flags().StringVar(&configPath, "config", "", "YAML extension selection file.")
	cmd.Flags().StringVar(&output, "output-dir", "", "Empty directory for incoming packages and batch-report.json.")
	cmd.Flags().StringVar(&privateKeyPath, "signing-key", "", "Dedicated collector Ed25519 PKCS8 PEM private key; keep it outside the share.")
	cmd.Flags().StringVar(&options.KeyID, "key-id", "", "Trusted collector public-key identifier.")
	cmd.Flags().DurationVar(&options.Validity, "valid-for", 168*time.Hour, "Publisher report validity, up to 30 days.")
	cmd.Flags().IntVar(&attempts, "attempts", 3, "Download attempts per extension, from 1 to 5.")
	return cmd
}

func loadCollectionConfig(filename string) (*collectionConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (256<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 256<<10 {
		return nil, fmt.Errorf("collection YAML exceeds 256 KiB")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	var validate func(*yaml.Node) error
	validate = func(node *yaml.Node) error {
		if node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" {
			return fmt.Errorf("collection YAML aliases, anchors, and merges are not supported")
		}
		for _, child := range node.Content {
			if err := validate(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := validate(&node); err != nil {
		return nil, err
	}
	config := &collectionConfig{PublisherMode: "verified"}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("one collection YAML document is required")
	}
	if len(config.Extensions) == 0 || len(config.Extensions) > 1000 {
		return nil, fmt.Errorf("select between 1 and 1000 extensions")
	}
	if err := storage.ValidateIdentity("publisher", "extension", storage.Version{Version: "1.0.0", TargetPlatform: config.TargetPlatform}); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range config.Extensions {
		entry := &config.Extensions[i]
		if entry.TargetPlatform == "" {
			entry.TargetPlatform = config.TargetPlatform
		}
		name, extension, ok := strings.Cut(entry.ID, ".")
		version := entry.Version
		if version == "" {
			version = "1.0.0"
		}
		if !ok {
			return nil, fmt.Errorf("extension %d must have a publisher.extension ID", i+1)
		}
		if err := storage.ValidateIdentity(name, extension, storage.Version{Version: version, TargetPlatform: entry.TargetPlatform}); err != nil {
			return nil, fmt.Errorf("extension %d: %w", i+1, err)
		}
		selection := strings.ToLower(fmt.Sprintf("%s|%s|%s|%t", entry.ID, entry.Version, entry.TargetPlatform, entry.PreRelease))
		if seen[selection] {
			return nil, fmt.Errorf("duplicate extension selection: %s", entry.ID)
		}
		seen[selection] = true
	}
	return config, nil
}

func (c *collectionConfig) policy(options publisher.CollectOptions) (*publisher.Policy, error) {
	if c.PublisherMode != "verified" && c.PublisherMode != "allowlist" && c.PublisherMode != "any" {
		return nil, fmt.Errorf("publisherMode must be verified, allowlist, or any")
	}
	policy := &publisher.Policy{Mode: c.PublisherMode, MaxAge: options.Validity, Keys: map[string]ed25519.PublicKey{options.KeyID: options.Key.Public().(ed25519.PublicKey)}, Allowed: map[string]bool{}}
	for _, name := range c.AllowedPublishers {
		name = strings.ToLower(name)
		if id, ok := strings.CutPrefix(name, "id:"); ok {
			parsed, err := uuid.Parse(id)
			if err != nil || parsed == uuid.Nil {
				return nil, fmt.Errorf("invalid allowed publisher ID")
			}
			name = "id:" + parsed.String()
		} else if err := storage.ValidateComponent(name); err != nil {
			return nil, err
		}
		policy.Allowed[name] = true
	}
	if c.PublisherMode == "any" && len(policy.Allowed) > 0 {
		return nil, fmt.Errorf("allowedPublishers requires verified or allowlist mode")
	}
	return policy, policy.Validate()
}

func runCollectionBatch(ctx context.Context, entries []collectionEntry, options publisher.CollectOptions, policy *publisher.Policy, incoming *os.Root, attempts int, collect func(context.Context, publisher.CollectOptions) (*publisher.Bundle, error), progress io.Writer) collectionReport {
	report := collectionReport{SchemaVersion: 1, StartedAt: time.Now().UTC(), Results: make([]collectionResult, 0, len(entries))}
	stored := map[string]publisher.Claims{}
	for i, entry := range entries {
		result := collectionResult{Request: entry, Status: "failed"}
		options.Extension, options.Version, options.Platform, options.PreRelease = entry.ID, entry.Version, entry.TargetPlatform, entry.PreRelease
		var bundle *publisher.Bundle
		var err error
		for attempt := 0; attempt < attempts; attempt++ {
			if err = ctx.Err(); err != nil {
				break
			}
			bundle, err = collect(ctx, options)
			if err == nil || attempt+1 == attempts {
				break
			}
			timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
			select {
			case <-ctx.Done():
			case <-timer.C:
			}
			timer.Stop()
		}
		if err == nil {
			_, err = policy.Verify(bundle.Report, bundle.VSIX, bundle.Signature, bundle.Manifest, time.Now().UTC())
		}
		if err == nil {
			name := storage.ExtensionVSIXNameFromManifest(bundle.Manifest)
			if existing, ok := stored[strings.ToLower(name)]; ok {
				if existing.SHA256 != bundle.Claims.SHA256 || existing.SignatureHash != bundle.Claims.SignatureHash {
					err = fmt.Errorf("conflicting packages resolve to the same filename: %s", name)
				} else {
					result.Status, result.Basename, result.Claims = "reused", name, &existing
					report.Reused++
				}
			} else if err = writeCollectedBundle(incoming, bundle); err == nil {
				claims := bundle.Claims
				stored[strings.ToLower(name)] = claims
				result.Status, result.Basename, result.Claims = "collected", name, &claims
				report.Collected++
			}
		}
		if err != nil {
			result.Error = err.Error()
			report.Failed++
		}
		report.Results = append(report.Results, result)
		fmt.Fprintf(progress, "[%d/%d] %s: %s", i+1, len(entries), entry.ID, result.Status)
		if result.Error != "" {
			fmt.Fprintf(progress, " (%s)", result.Error)
		}
		fmt.Fprintln(progress)
	}
	report.FinishedAt = time.Now().UTC()
	return report
}

func writeCollectionReport(root *os.Root, data []byte) error {
	file, err := root.OpenFile("batch-report.json.part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return root.Rename("batch-report.json.part", "batch-report.json")
}
