package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/einyx/s3proxy-go/internal/config"
	"github.com/einyx/s3proxy-go/internal/proxy"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "s3proxy",
		Short: "S3 proxy server",
		Long:  `A high-performance S3 proxy server that can proxy requests to various storage backends including Azure Blob Storage`,
		RunE:  run,
	}

	rootCmd.Flags().StringP("config", "c", "", "config file path")
	rootCmd.Flags().String("listen", ":8080", "listen address")
	rootCmd.Flags().String("log-level", "info", "log level (debug, info, warn, error)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, _ []string) error {
	logLevel, _ := cmd.Flags().GetString("log-level")
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	if level < logrus.WarnLevel {
		level = logrus.WarnLevel
	}
	logrus.SetLevel(level)

	logrus.SetFormatter(&logrus.JSONFormatter{})

	logrus.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
		"date":    date,
		"num_cpu": runtime.NumCPU(),
	}).Info("Starting S3 proxy server")

	configFile, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	listenAddr, _ := cmd.Flags().GetString("listen")
	if listenAddr != "" {
		cfg.Server.Listen = listenAddr
	}

	logrus.WithFields(logrus.Fields{
		"storage_provider": cfg.Storage.Provider,
		"auth_type":        cfg.Auth.Type,
		"listen_addr":      cfg.Server.Listen,
		"s3_config": logrus.Fields{
			"region":         cfg.S3.Region,
			"ignore_headers": cfg.S3.IgnoreUnknownHeaders,
		},
	}).Info("Configuration loaded")

	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           proxyServer,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       300 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ReadHeaderTimeout: 2 * time.Second,

		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateNew {
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.SetNoDelay(true)
					_ = tcpConn.SetKeepAlive(true)
					_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
				}
			}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		logrus.Info("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logrus.WithError(err).Error("Failed to shutdown server gracefully")
		}
		cancel()
	}()

	logrus.WithField("addr", cfg.Server.Listen).Info("Server listening")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-ctx.Done()
	logrus.Info("Server stopped")
	return nil
}
