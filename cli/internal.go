package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/spf13/cobra"
)

var internalKeyID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func internalCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "internal", Short: "Prepare offline release attestations for internal VSIX packages"}
	cmd.AddCommand(internalKeygenCommand(), internalSignCommand())
	return cmd
}

func internalKeygenCommand() *cobra.Command {
	var output, keyID string
	cmd := &cobra.Command{
		Use:   "keygen <publisher.extension> [publisher.extension...]",
		Short: "Generate a dedicated release key and its scoped public importer policy",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, extensions []string) error {
			if output == "" || !internalKeyID.MatchString(keyID) {
				return fmt.Errorf("--output-dir and a valid --key-id are required")
			}
			for _, extension := range extensions {
				pub, name, ok := strings.Cut(extension, ".")
				if !ok || storage.ValidateComponent(pub) != nil || storage.ValidateComponent(name) != nil {
					return fmt.Errorf("invalid internal extension ID %q", extension)
				}
			}
			root, err := openCollectorOutput(output)
			if err != nil {
				return err
			}
			defer root.Close()
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			encoded, err := x509.MarshalPKCS8PrivateKey(private)
			if err != nil {
				return err
			}
			policy, err := json.MarshalIndent(map[string]any{"keys": map[string]any{
				keyID: map[string]any{"publicKey": base64.StdEncoding.EncodeToString(public), "extensions": extensions},
			}}, "", "  ")
			if err != nil {
				return err
			}
			if err := writeNewInternalFile(root, "internal-private.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})); err != nil {
				return err
			}
			if err := writeNewInternalFile(root, "internal-policy.json", policy); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "Created internal-policy.json and internal-private.pem in", output)
			return err
		},
	}
	cmd.Flags().StringVar(&output, "output-dir", "", "Empty, protected output directory.")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Unique internal release key identifier.")
	return cmd
}

func internalSignCommand() *cobra.Command {
	var keyPath, keyID, outputDir string
	var validity time.Duration
	cmd := &cobra.Command{
		Use:   "sign <file.vsix>",
		Short: "Sign one local VSIX without changing the package",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" || !internalKeyID.MatchString(keyID) || !strings.EqualFold(filepath.Ext(args[0]), ".vsix") {
				return fmt.Errorf("a local VSIX, --signing-key and a valid --key-id are required")
			}
			source, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			input, err := os.OpenRoot(filepath.Dir(source))
			if err != nil {
				return err
			}
			defer input.Close()
			vsix, err := storage.ReadPrivateFile(input, filepath.Base(source), storage.MaxPackageSize)
			if err != nil {
				return err
			}
			manifest, err := storage.ReadVSIXManifest(vsix)
			if err != nil {
				return err
			}
			if err := storage.ValidatePackage(manifest, vsix); err != nil {
				return err
			}
			key, err := readCollectorKey(keyPath)
			if err != nil {
				return err
			}
			report, err := publisher.SignInternal(vsix, manifest, keyID, key, time.Now(), validity)
			if err != nil {
				return err
			}
			if outputDir == "" {
				outputDir = filepath.Dir(source)
			}
			output, err := os.OpenRoot(outputDir)
			if err != nil {
				return err
			}
			defer output.Close()
			name := strings.TrimSuffix(filepath.Base(source), filepath.Ext(source)) + publisher.InternalReportSuffix
			if err := writeNewInternalFile(output, name, report); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), filepath.Join(outputDir, name))
			return err
		},
	}
	cmd.Flags().StringVar(&keyPath, "signing-key", "", "Dedicated Ed25519 PKCS#8 private key.")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Configured internal release key identifier.")
	cmd.Flags().StringVar(&outputDir, "output-dir", "", "Existing directory for the new report. Defaults to the VSIX directory.")
	cmd.Flags().DurationVar(&validity, "valid-for", 24*time.Hour, "Release report validity, up to seven days.")
	return cmd
}

func writeNewInternalFile(root *os.Root, name string, data []byte) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		root.Remove(name)
		if err != nil {
			return err
		}
	}
	return closeErr
}
