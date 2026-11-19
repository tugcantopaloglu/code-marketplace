package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/signal"
	"time"

	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/spf13/cobra"
)

func importCommand() *cobra.Command {
	var incoming, destination, trust string
	var maxAge time.Duration
	var sandboxMode string
	var publisherMode, publisherPolicyPath string
	var internalPolicyPath string
	var autoSignKeyPath string
	var autoSign ingest.InternalAutoSign
	var publisherMaxAge time.Duration
	var processed string
	var writeIncomingReport bool
	cmd := &cobra.Command{
		Use: "import", Short: "Import signed local packages with configured admission policies",
		RunE: func(cmd *cobra.Command, _ []string) (runErr error) {
			started := time.Now().UTC()
			runStarted := false
			defer func() {
				if !runStarted && runErr != nil && writeIncomingReport {
					if err := ingest.WriteIncomingFailure(incoming, destination, started, runErr); err != nil {
						runErr = errors.Join(runErr, fmt.Errorf("write incoming failure report: %w", err))
					}
				}
			}()
			if incoming == "" || destination == "" {
				return fmt.Errorf("--incoming-dir and --extensions-dir are required")
			}
			if sandboxMode != "required" && sandboxMode != "disabled" {
				return fmt.Errorf("--sandbox-mode must be required or disabled")
			}
			publisherPolicy, err := publisher.LoadPolicy(publisherPolicyPath, publisherMode, publisherMaxAge)
			if err != nil {
				return err
			}
			var internalPolicy *publisher.InternalPolicy
			if internalPolicyPath != "" {
				internalPolicy, err = publisher.LoadInternalPolicy(internalPolicyPath)
				if err != nil {
					return err
				}
			}
			var automatic *ingest.InternalAutoSign
			if cmd.Flags().Changed("internal-auto-sign-key") || cmd.Flags().Changed("internal-auto-sign-key-id") || cmd.Flags().Changed("internal-uploader-uid") || autoSign.SkipSandbox {
				if internalPolicy == nil || autoSignKeyPath == "" || !internalKeyID.MatchString(autoSign.KeyID) || !cmd.Flags().Changed("internal-uploader-uid") {
					return fmt.Errorf("automatic internal signing requires --internal-policy, --internal-auto-sign-key, --internal-auto-sign-key-id and --internal-uploader-uid")
				}
				autoSign.Key, err = readCollectorKey(autoSignKeyPath)
				if err != nil {
					return fmt.Errorf("load internal automatic signing key: %w", err)
				}
				automatic = &autoSign
			}
			var policy *sandbox.Policy
			if trust != "" {
				if sandboxMode == "disabled" && internalPolicy == nil {
					return fmt.Errorf("--sandbox-trust must be omitted in disabled sandbox mode")
				}
				policy, err = sandbox.LoadPolicy(trust, maxAge)
				if err != nil {
					return err
				}
			} else if sandboxMode == "required" || internalPolicy != nil && !autoSign.SkipSandbox {
				return fmt.Errorf("--sandbox-trust is required for packages subject to mandatory sandbox admission")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), interruptSignals...)
			defer stop()
			runStarted = true
			summary, err := ingest.Run(ctx, ingest.Options{Incoming: incoming, Storage: destination, SandboxMode: sandboxMode, Policy: policy, PublisherPolicy: publisherPolicy, InternalPolicy: internalPolicy, InternalAutoSign: automatic, Logger: cmdLogger(cmd), Processed: processed, WriteIncomingReport: writeIncomingReport})
			if summary != nil {
				if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(summary); writeErr != nil {
					return writeErr
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&incoming, "incoming-dir", "", "Share directory containing VSIX, signature, and sandbox report files.")
	cmd.Flags().StringVar(&destination, "extensions-dir", "", "Published local extension storage.")
	cmd.Flags().StringVar(&processed, "processed-dir", "", "Archive successfully published VSIX bundles here; disabled when omitted.")
	cmd.Flags().BoolVar(&writeIncomingReport, "write-incoming-report", false, "Atomically update incoming/import-report.json with progress, decisions, and failures.")
	cmd.Flags().StringVar(&trust, "sandbox-trust", "", "Trusted sandbox public keys JSON file.")
	cmd.Flags().StringVar(&sandboxMode, "sandbox-mode", "required", "Sandbox admission: required, or explicitly disabled for temporary operation.")
	cmd.Flags().DurationVar(&maxAge, "sandbox-max-age", 24*time.Hour, "Maximum sandbox report age and validity interval.")
	cmd.Flags().StringVar(&publisherMode, "publisher-mode", "verified", "Publisher restriction: verified, allowlist, or any. Verified mode also applies a configured allowlist.")
	cmd.Flags().StringVar(&publisherPolicyPath, "publisher-policy", "", "Trusted publisher collector keys and allowed publisher names JSON file.")
	cmd.Flags().StringVar(&internalPolicyPath, "internal-policy", "", "Optional trusted release keys and exact extension IDs for internal VSIX packages.")
	cmd.Flags().StringVar(&autoSignKeyPath, "internal-auto-sign-key", "", "Optional dedicated Ed25519 private key for automatic internal release reports.")
	cmd.Flags().StringVar(&autoSign.KeyID, "internal-auto-sign-key-id", "", "ID of the automatic release key in the internal policy.")
	cmd.Flags().Uint32Var(&autoSign.UploaderUID, "internal-uploader-uid", 0, "Linux UID of the trusted uploader for automatic signing of internal-*.vsix.")
	cmd.Flags().BoolVar(&autoSign.SkipSandbox, "internal-auto-skip-sandbox", false, "Allow only authorized internal-* uploads to be automatically imported without a sandbox report.")
	cmd.Flags().DurationVar(&publisherMaxAge, "publisher-max-age", 7*24*time.Hour, "Maximum age and validity interval of publisher provenance reports.")
	return cmd
}
