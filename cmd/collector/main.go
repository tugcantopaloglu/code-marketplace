package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/coder/code-marketplace/collector"
	"github.com/coder/code-marketplace/storage"
)

func main() {
	options := collector.Options{}
	var platform, address string
	var noOpen bool
	flag.StringVar(&address, "address", "127.0.0.1:0", "Loopback address (a free port is chosen by default).")
	flag.StringVar(&options.DataDir, "data-dir", "", "Workstation private configuration directory.")
	flag.StringVar(&options.Destination, "output-dir", "", "Initial download parent folder.")
	flag.StringVar(&options.SigningKey, "signing-key", "", "Existing collector private key (administrator configuration).")
	flag.StringVar(&options.KeyID, "key-id", "", "Existing trusted collector key identifier.")
	flag.StringVar(&platform, "target-platform", "win32-x64", "Target editor platform (administrator configuration).")
	flag.BoolVar(&noOpen, "no-open", false, "Do not launch the browser automatically.")
	flag.Parse()
	options.Platform = storage.Platform(platform)
	if err := run(options, address, noOpen); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		if !noOpen {
			collector.ShowError("Program başlatılamadı: " + err.Error())
		}
		os.Exit(1)
	}
}

func run(options collector.Options, address string, noOpen bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return fmt.Errorf("yalnızca loopback adresi kullanılabilir")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	options.OnClose = stop
	origin := "http://" + listener.Addr().String()
	handler, err := collector.New(ctx, origin, options)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	// The capability URL is kept only in this user's private configuration.
	if err := handler.SaveLaunchURL(); err != nil {
		return fmt.Errorf("özel oturum adresi kaydedilemedi: %w", err)
	}
	fmt.Println(origin)
	if !noOpen {
		go func() {
			if err := collector.OpenBrowser(handler.LaunchURL()); err != nil {
				collector.ShowError("Tarayıcı açılamadı. Varsayılan tarayıcınızı kontrol edip EXE dosyasını yeniden açın.")
			}
		}()
	}
	err = server.Serve(listener)
	handler.Wait()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
