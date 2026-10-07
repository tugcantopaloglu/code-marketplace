package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/spf13/cobra"
)

func importCommand() *cobra.Command {
	var incoming, destination, trust string
	var maxAge time.Duration
	var publisherMode, publisherPolicyPath string
	var publisherMaxAge time.Duration
	cmd := &cobra.Command{
		Use: "import", Short: "Import signed local packages with authenticated sandbox approval",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if incoming == "" || destination == "" || trust == "" {
				return fmt.Errorf("--incoming-dir, --extensions-dir, and --sandbox-trust are required")
			}
			policy, err := sandbox.LoadPolicy(trust, maxAge)
			if err != nil {
				return err
			}
			publisherPolicy, err := publisher.LoadPolicy(publisherPolicyPath, publisherMode, publisherMaxAge)
			if err != nil {
				return err
			}
			summary, err := ingest.Run(cmd.Context(), ingest.Options{Incoming: incoming, Storage: destination, Policy: policy, PublisherPolicy: publisherPolicy, Logger: cmdLogger(cmd)})
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
	cmd.Flags().StringVar(&trust, "sandbox-trust", "", "Trusted sandbox public keys JSON file.")
	cmd.Flags().DurationVar(&maxAge, "sandbox-max-age", 24*time.Hour, "Maximum sandbox report age and validity interval.")
	cmd.Flags().StringVar(&publisherMode, "publisher-mode", "verified", "Publisher restriction: verified, allowlist, or any. Verified mode also applies a configured allowlist.")
	cmd.Flags().StringVar(&publisherPolicyPath, "publisher-policy", "", "Trusted publisher collector keys and allowed publisher names JSON file.")
	cmd.Flags().DurationVar(&publisherMaxAge, "publisher-max-age", 7*24*time.Hour, "Maximum age and validity interval of publisher provenance reports.")
	return cmd
}
