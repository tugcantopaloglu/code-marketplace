package cli

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os/signal"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/management"
	"github.com/spf13/cobra"
)

func adminCommand() *cobra.Command {
	var filename string
	cmd := &cobra.Command{Use: "admin", Short: "Start the AD-authenticated management service from YAML", RunE: func(cmd *cobra.Command, _ []string) error {
		config, err := management.LoadConfig(filename)
		if err != nil {
			return err
		}
		handler, err := management.New(*config, nil)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", config.Address)
		if err != nil {
			return err
		}
		defer listener.Close()
		ctx, stop := signal.NotifyContext(cmd.Context(), interruptSignals...)
		defer stop()
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(_ net.Listener) context.Context { return ctx }}
		cmdLogger(cmd).Info(ctx, "Started management server", slog.F("address", listener.Addr()), slog.F("public_url", config.PublicURL))
		finished := make(chan error, 1)
		go func() { finished <- server.Serve(listener) }()
		select {
		case err := <-finished:
			if !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-ctx.Done():
		}
		timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(timeout)
	}}
	cmd.Flags().StringVar(&filename, "config", "", "Management YAML configuration file.")
	cmd.MarkFlagRequired("config")
	return cmd
}
