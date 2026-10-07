package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/util"
)

func add() *cobra.Command {
	addFlags, opts := serverFlags()
	var signatureSource string
	var requireSignature bool
	var trustPath, reportPath string
	var requireReport bool
	var reportMaxAge time.Duration
	cmd := &cobra.Command{
		Use:   "add <source>",
		Short: "Add an extension to the marketplace",
		Example: strings.Join([]string{
			"  marketplace add https://domain.tld/extension.vsix --extensions-dir ./extensions",
			"  marketplace add extension.vsix --artifactory http://artifactory.server/artifactory --repo extensions",
			"  marketplace add extension-vsixs/ --extensions-dir ./extensions",
		}, "\n"),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			var policy *sandbox.Policy
			if requireReport || reportPath != "" || trustPath != "" {
				if trustPath == "" {
					return fmt.Errorf("--sandbox-trust is required for sandbox approval")
				}
				var err error
				policy, err = sandbox.LoadPolicy(trustPath, reportMaxAge)
				if err != nil {
					return err
				}
			}

			store, err := storage.NewStorage(ctx, opts)
			if err != nil {
				return err
			}

			// The source might be a local directory with extensions.
			isDir := false
			if !strings.HasPrefix(args[0], "http://") && !strings.HasPrefix(args[0], "https://") {
				stat, err := os.Stat(args[0])
				if err != nil {
					return err
				}
				isDir = stat.IsDir()
			}
			if isDir && signatureSource != "" {
				return xerrors.Errorf("--signature requires a single VSIX file or URL")
			}
			if isDir && reportPath != "" {
				return fmt.Errorf("--sandbox-report requires a single local VSIX")
			}
			if policy != nil && (strings.HasPrefix(args[0], "http://") || strings.HasPrefix(args[0], "https://")) {
				return fmt.Errorf("sandbox approval requires a local VSIX")
			}

			var failed []string
			if isDir {
				files, err := os.ReadDir(args[0])
				if err != nil {
					return err
				}
				for _, file := range files {
					if file.IsDir() || !strings.EqualFold(filepath.Ext(file.Name()), ".vsix") {
						continue
					}
					s, err := doAdd(ctx, filepath.Join(args[0], file.Name()), "", requireSignature, policy, "", store)
					if err != nil {
						_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Failed to unpack %s: %s\n", file.Name(), err.Error())
						failed = append(failed, file.Name())
					} else {
						_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Join(s, "\n"))
					}
				}
			} else {
				s, err := doAdd(ctx, args[0], signatureSource, requireSignature, policy, reportPath, store)
				if err != nil {
					return err
				}
				_, _ = fmt.Fprintln(cmd.OutOrStdout(), strings.Join(s, "\n"))
			}

			if len(failed) > 0 {
				return xerrors.Errorf(
					"Failed to add %s: %s",
					util.Plural(len(failed), "extension", ""),
					strings.Join(failed, ", "))
			}
			return nil
		},
	}
	addFlags(cmd)
	cmd.Flags().StringVar(&signatureSource, "signature", "", "The detached signature archive file or URL for this VSIX.")
	cmd.Flags().BoolVar(&requireSignature, "require-signature", false, "Reject packages without a matching signature archive.")
	cmd.Flags().BoolVar(&requireReport, "require-sandbox-report", false, "Require an authenticated clean sandbox report before importing.")
	cmd.Flags().StringVar(&trustPath, "sandbox-trust", "", "Trusted sandbox public keys JSON file; enables mandatory sandbox approval.")
	cmd.Flags().StringVar(&reportPath, "sandbox-report", "", "Sandbox report for a single local VSIX; defaults to the matching .sandbox.json sidecar.")
	cmd.Flags().DurationVar(&reportMaxAge, "sandbox-max-age", 24*time.Hour, "Maximum age and validity interval of sandbox reports.")

	return cmd
}

func doAdd(ctx context.Context, source, signatureSource string, requireSignature bool, policy *sandbox.Policy, reportPath string, store storage.Storage) ([]string, error) {
	if signatureSource == "" && !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
		candidate := strings.TrimSuffix(source, filepath.Ext(source)) + ".sigzip"
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			signatureSource = candidate
		}
	}
	if requireSignature && signatureSource == "" {
		return nil, xerrors.Errorf("signature archive is required for %q", source)
	}
	// Read in the extension.  In the future we might support stdin as well.
	vsix, err := storage.ReadVSIX(ctx, source)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		if reportPath == "" {
			reportPath = strings.TrimSuffix(source, filepath.Ext(source)) + ".sandbox.json"
		}
		report, err := sandbox.ReadFile(reportPath)
		if err != nil {
			return nil, fmt.Errorf("sandbox report is required: %w", err)
		}
		if _, err := policy.Verify(report, vsix, time.Now().UTC()); err != nil {
			return nil, err
		}
	}

	// The manifest is required to know where to place the extension since it
	// is unsafe to rely on the file name or URI.
	manifest, err := storage.ReadVSIXManifest(vsix)
	if err != nil {
		return nil, err
	}

	var extra []storage.File
	if signatureSource != "" {
		signature, err := storage.ReadVSIX(ctx, signatureSource)
		if err != nil {
			return nil, xerrors.Errorf("read signature archive: %w", err)
		}
		extra = append(extra, storage.File{
			RelativePath: storage.SignatureArchiveFilename(manifest),
			Content:      signature,
		})
	}
	location, err := store.AddExtension(ctx, manifest, vsix, extra...)
	if err != nil {
		return nil, err
	}

	deps := []string{}
	pack := []string{}
	for _, prop := range manifest.Metadata.Properties.Property {
		if prop.Value == "" {
			continue
		}
		switch prop.ID {
		case storage.DependencyPropertyType:
			deps = append(deps, strings.Split(prop.Value, ",")...)
		case storage.PackPropertyType:
			pack = append(pack, strings.Split(prop.Value, ",")...)
		}
	}

	depCount := len(deps)
	id := storage.ExtensionIDFromManifest(manifest)
	summary := []string{
		fmt.Sprintf("Unpacked %s to %s", id, location),
		fmt.Sprintf("  - %s has %s", id, util.Plural(depCount, "dependency", "dependencies")),
	}

	if depCount > 0 {
		for _, id := range deps {
			summary = append(summary, fmt.Sprintf("    - %s", id))
		}
	}

	packCount := len(pack)
	if packCount > 0 {
		summary = append(summary, fmt.Sprintf("  - %s is in a pack with %s", id, util.Plural(packCount, "other extension", "")))
		for _, id := range pack {
			summary = append(summary, fmt.Sprintf("    - %s", id))
		}
	} else {
		summary = append(summary, fmt.Sprintf("  - %s is not in a pack", id))
	}

	return summary, nil
}
