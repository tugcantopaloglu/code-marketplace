package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/spf13/cobra"
)

func collectCommand() *cobra.Command {
	var output, privateKeyPath, platform string
	options := publisher.CollectOptions{}
	cmd := &cobra.Command{Use: "collect", Short: "Download Marketplace bytes and attest publisher metadata on a connected collector host", RunE: func(cmd *cobra.Command, _ []string) error {
		if output == "" || privateKeyPath == "" {
			return fmt.Errorf("--output-dir and --signing-key are required")
		}
		key, err := readCollectorKey(privateKeyPath)
		if err != nil {
			return err
		}
		root, err := openCollectorOutput(output)
		if err != nil {
			return err
		}
		defer root.Close()
		options.Key, options.Platform = key, storage.Platform(platform)
		bundle, err := publisher.Collect(cmd.Context(), options)
		if err != nil {
			return err
		}
		if err := writeCollectedBundle(root, bundle); err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(bundle.Claims)
	}}
	cmd.Flags().StringVar(&options.Extension, "extension", "", "Marketplace publisher.extension ID.")
	cmd.Flags().StringVar(&options.Version, "version", "", "Exact version; defaults to the latest compatible version.")
	cmd.Flags().BoolVar(&options.PreRelease, "pre-release", false, "Include pre-release versions when selecting the latest package.")
	cmd.Flags().StringVar(&platform, "target-platform", "", "Target platform; defaults to universal packages.")
	cmd.Flags().StringVar(&output, "output-dir", "", "Empty collector output directory.")
	cmd.Flags().StringVar(&privateKeyPath, "signing-key", "", "Dedicated collector Ed25519 PKCS8 PEM private key; keep it outside the share.")
	cmd.Flags().StringVar(&options.KeyID, "key-id", "", "Trusted collector public-key identifier.")
	cmd.Flags().DurationVar(&options.Validity, "valid-for", 24*time.Hour, "Publisher report validity, up to 30 days.")
	return cmd
}

func readCollectorKey(filename string) (ed25519.PrivateKey, error) {
	data, err := sandbox.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, fmt.Errorf("collector signing key must be a PKCS8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("collector signing key must use Ed25519")
	}
	return key, nil
}

func openCollectorOutput(output string) (*os.Root, error) {
	if err := os.MkdirAll(output, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(output)
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil || len(entries) != 0 {
		root.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("collector output directory must be empty")
	}
	return root, nil
}

func writeCollectedBundle(root *os.Root, bundle *publisher.Bundle) error {
	name := storage.ExtensionVSIXNameFromManifest(bundle.Manifest)
	files := []struct {
		name string
		data []byte
	}{{name + ".sigzip", bundle.Signature}, {name + ".publisher.json", bundle.Report}, {name + ".vsix", bundle.VSIX}}
	for _, file := range files {
		if _, err := root.Lstat(file.name); !os.IsNotExist(err) {
			return fmt.Errorf("collector destination already exists or is unavailable: %s", file.name)
		}
	}
	var created []string
	complete := false
	defer func() {
		if !complete {
			for _, name := range created {
				root.Remove(name)
			}
		}
	}()
	for _, file := range files {
		writer, err := root.OpenFile(file.name+".part", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		created = append(created, file.name+".part")
		_, err = writer.Write(file.data)
		if err == nil {
			err = writer.Sync()
		}
		closeErr := writer.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	for _, file := range files {
		if err := root.Rename(file.name+".part", file.name); err != nil {
			return err
		}
		created = append(created, file.name)
	}
	complete = true
	return nil
}
