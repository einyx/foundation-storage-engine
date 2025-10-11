package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/getsentry/sentry-go"
	slogsentry "github.com/getsentry/sentry-go/slog"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/logging"
	"github.com/einyx/foundation-storage-engine/internal/proxy"
)

const (
	// Server configuration constants
	maxHeaderBytes        = 1 << 20        // 1MB
	readHeaderTimeout     = 2 * time.Second
	shutdownTimeout       = 30 * time.Second
	sentryFlushTimeout    = 2 * time.Second
	tcpKeepAlivePeriod    = 30 * time.Second
	
	// Cache configuration constants
	defaultMaxMemory      = 1024 * 1024 * 1024 // 1GB
	defaultMaxObjectSize  = 10 * 1024 * 1024   // 10MB
	defaultCacheTTL       = 5 * time.Minute
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "foundation-storage-engine",
		Short: "Foundation Storage Engine",
		Long:  `A high-performance S3-compatible storage engine that can proxy requests to various storage backends including Azure Blob Storage`,
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
	logrus.SetLevel(level)

	logrus.SetFormatter(&logrus.JSONFormatter{})

	logrus.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
		"date":    date,
		"num_cpu": runtime.NumCPU(),
	}).Info("Starting S3 proxy server")

	configFile, _ := cmd.Flags().GetString("config")
	appConfig, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize Sentry
	if appConfig.Sentry.Enabled {
		if err := initSentry(appConfig); err != nil {
			logrus.WithError(err).Error("Failed to initialize Sentry")
			// Don't fail startup if Sentry init fails
		} else {
			defer sentry.Flush(sentryFlushTimeout)
			logrus.Info("Sentry initialized successfully")
			
			// Set up slog with Sentry handler for proper log support
			sentryHandler := slogsentry.Option{
				Level: slog.LevelInfo,  // Send info and above as logs
				Hub: sentry.CurrentHub(),
			}.NewSentryHandler(context.Background())
			
			// Create a multi-handler that sends to both console and Sentry
			logger := slog.New(sentryHandler)
			slog.SetDefault(logger)
			
			// Test slog logging to Sentry
			slog.Info("Foundation Storage Engine started", 
				"version", version,
				"commit", commit,
				"sentry", "enabled")
			
			// Also send logrus errors to Sentry as events (for backwards compatibility)
			sentryLevels := []logrus.Level{
				logrus.PanicLevel,
				logrus.FatalLevel,
				logrus.ErrorLevel,
				logrus.WarnLevel,
			}
			
			// Add our custom Sentry hook for logrus events
			logrus.AddHook(logging.NewSentryHook(sentryLevels))
			
			// Optionally add breadcrumb hook for better debugging context
			if appConfig.Sentry.Debug || appConfig.Sentry.MaxBreadcrumbs > 0 {
				logrus.AddHook(logging.NewBreadcrumbHook([]logrus.Level{
					logrus.InfoLevel,
					logrus.WarnLevel,
					logrus.ErrorLevel,
				}))
			}
		}
	}

	listenAddr, _ := cmd.Flags().GetString("listen")
	if listenAddr != "" {
		appConfig.Server.Listen = listenAddr
	}

	logrus.WithFields(logrus.Fields{
		"storage_provider": appConfig.Storage.Provider,
		"auth_type":        appConfig.Auth.Type,
		"listen_addr":      appConfig.Server.Listen,
		"s3_config": logrus.Fields{
			"region":         appConfig.S3.Region,
			"ignore_headers": appConfig.S3.IgnoreUnknownHeaders,
		},
	}).Info("Configuration loaded")

	proxyServer, err := proxy.NewServer(appConfig)
	if err != nil {
		return fmt.Errorf("failed to create proxy server: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"readTimeout":  appConfig.Server.ReadTimeout,
		"writeTimeout": appConfig.Server.WriteTimeout,
		"idleTimeout":  appConfig.Server.IdleTimeout,
		"listen":       appConfig.Server.Listen,
	}).Info("Starting HTTP server with configured timeouts")
	
	srv := &http.Server{
		Addr:              appConfig.Server.Listen,
		Handler:           proxyServer,
		ReadTimeout:       appConfig.Server.ReadTimeout,
		WriteTimeout:      appConfig.Server.WriteTimeout,
		IdleTimeout:       appConfig.Server.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: readHeaderTimeout,

		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateNew {
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.SetNoDelay(true)
					_ = tcpConn.SetKeepAlive(true)
					_ = tcpConn.SetKeepAlivePeriod(tcpKeepAlivePeriod)
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
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logrus.WithError(err).Error("Failed to shutdown server gracefully")
		}
		// Close proxy server resources (including database connections)
		if err := proxyServer.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close proxy server resources")
		}
		cancel()
	}()

	logrus.WithField("addr", appConfig.Server.Listen).Info("Server listening")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-ctx.Done()
	logrus.Info("Server stopped")
	return nil
}

func initSentry(appConfig *config.Config) error {
	options := sentry.ClientOptions{
		Dsn:              appConfig.Sentry.DSN,
		Environment:      appConfig.Sentry.Environment,
		Release:          appConfig.Sentry.Release,
		SampleRate:       appConfig.Sentry.SampleRate,
		TracesSampleRate: appConfig.Sentry.TracesSampleRate,
		AttachStacktrace: appConfig.Sentry.AttachStacktrace,
		EnableTracing:    appConfig.Sentry.EnableTracing,
		Debug:            appConfig.Sentry.Debug,
		MaxBreadcrumbs:   appConfig.Sentry.MaxBreadcrumbs,
		ServerName:       appConfig.Sentry.ServerName,
		EnableLogs:       true,
	}

	// Set release version if not provided in config
	if options.Release == "" {
		options.Release = fmt.Sprintf("foundation-storage-engine@%s", version)
	}

	// Note: BeforeSendTimeout and FlushTimeout are not directly configurable in the current SDK version
	// The SDK uses reasonable defaults for these timeouts

	// Configure BeforeSend to filter events
	options.BeforeSend = func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
		// Filter out metrics endpoint logs unless they're errors
		if event.Level != sentry.LevelError && event.Level != sentry.LevelFatal {
			for _, breadcrumb := range event.Breadcrumbs {
				if path, ok := breadcrumb.Data["path"].(string); ok && path == "/metrics" {
					return nil // Drop metrics events that aren't errors
				}
			}
			if event.Request != nil && event.Request.URL == "/metrics" {
				return nil // Drop metrics events
			}
			// Check tags
			if path, ok := event.Tags["http.path"]; ok && path == "/metrics" {
				return nil
			}
		}
		
		// Check for ignored errors
		if hint.OriginalException != nil {
			errMsg := hint.OriginalException.Error()
			for _, ignore := range appConfig.Sentry.IgnoreErrors {
				if strings.Contains(errMsg, ignore) {
					return nil // Drop the event
				}
			}
		}
		return event
	}

	// Add server tags
	options.Tags = map[string]string{
		"server.version": version,
		"server.commit":  commit,
		"server.date":    date,
	}

	// Note: ProfilesSampleRate requires the profiling integration
	// which needs to be enabled separately

	return sentry.Init(options)
}
