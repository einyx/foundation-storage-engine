package main

import (
	"fmt"
	"log"
	"os"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/einyx/foundation-storage-engine/internal/database"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "user-manager",
		Short: "User management CLI for foundation-storage-engine",
	}

	var dbConfig database.Config
	var configFile string

	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "config file path")
	rootCmd.PersistentFlags().StringVar(&dbConfig.ConnectionString, "db-connection", "", "database connection string")
	rootCmd.PersistentFlags().StringVar(&dbConfig.Driver, "db-driver", "postgres", "database driver")

	// Create user command
	var createCmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		Run: func(cmd *cobra.Command, args []string) {
			db, um := setupDatabase(configFile, dbConfig)
			defer db.Close()

			email, _ := cmd.Flags().GetString("email")
			password, _ := cmd.Flags().GetString("password")
			accessKey, _ := cmd.Flags().GetString("access-key")
			secretKey, _ := cmd.Flags().GetString("secret-key")

			var user *database.User
			var err error

			if accessKey != "" && secretKey != "" {
				user, err = um.CreateUserWithKeys(email, accessKey, secretKey)
			} else if password != "" {
				user, err = um.CreateUser(email, password)
			} else {
				log.Fatal("Either --password or both --access-key and --secret-key must be provided")
			}

			if err != nil {
				log.Fatalf("Failed to create user: %v", err)
			}

			fmt.Printf("User created successfully:\n")
			fmt.Printf("Email: %s\n", user.Email)
			fmt.Printf("Access Key: %s\n", user.AccessKey)
			fmt.Printf("Active: %v\n", user.Active)
		},
	}

	createCmd.Flags().String("email", "", "User email")
	createCmd.Flags().String("password", "", "User password (will be hashed)")
	createCmd.Flags().String("access-key", "", "Custom access key")
	createCmd.Flags().String("secret-key", "", "Custom secret key")
	createCmd.MarkFlagRequired("email")

	// List users command
	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all users",
		Run: func(cmd *cobra.Command, args []string) {
			db, um := setupDatabase(configFile, dbConfig)
			defer db.Close()

			users, err := um.ListUsers()
			if err != nil {
				log.Fatalf("Failed to list users: %v", err)
			}

			fmt.Printf("%-20s %-30s %-8s %-20s %-20s\n", "Access Key", "Email", "Active", "Created", "Last Login")
			fmt.Println(string(make([]byte, 100)))

			for _, user := range users {
				lastLogin := "Never"
				if user.LastLogin != nil {
					lastLogin = user.LastLogin.Format("2006-01-02 15:04:05")
				}
				fmt.Printf("%-20s %-30s %-8v %-20s %-20s\n",
					user.AccessKey,
					user.Email,
					user.Active,
					user.CreatedAt.Format("2006-01-02 15:04:05"),
					lastLogin,
				)
			}
		},
	}

	// Disable user command
	var disableCmd = &cobra.Command{
		Use:   "disable",
		Short: "Disable a user",
		Run: func(cmd *cobra.Command, args []string) {
			db, um := setupDatabase(configFile, dbConfig)
			defer db.Close()

			accessKey, _ := cmd.Flags().GetString("access-key")
			
			err := um.DisableUser(accessKey)
			if err != nil {
				log.Fatalf("Failed to disable user: %v", err)
			}

			fmt.Printf("User %s disabled successfully\n", accessKey)
		},
	}

	disableCmd.Flags().String("access-key", "", "User access key")
	disableCmd.MarkFlagRequired("access-key")

	// Enable user command
	var enableCmd = &cobra.Command{
		Use:   "enable",
		Short: "Enable a user",
		Run: func(cmd *cobra.Command, args []string) {
			db, um := setupDatabase(configFile, dbConfig)
			defer db.Close()

			accessKey, _ := cmd.Flags().GetString("access-key")
			
			err := um.EnableUser(accessKey)
			if err != nil {
				log.Fatalf("Failed to enable user: %v", err)
			}

			fmt.Printf("User %s enabled successfully\n", accessKey)
		},
	}

	enableCmd.Flags().String("access-key", "", "User access key")
	enableCmd.MarkFlagRequired("access-key")

	// Grant permission command
	var grantCmd = &cobra.Command{
		Use:   "grant",
		Short: "Grant bucket permission to a user",
		Run: func(cmd *cobra.Command, args []string) {
			db, um := setupDatabase(configFile, dbConfig)
			defer db.Close()

			accessKey, _ := cmd.Flags().GetString("access-key")
			bucket, _ := cmd.Flags().GetString("bucket")
			permissions, _ := cmd.Flags().GetString("permissions")
			
			err := um.GrantBucketPermission(accessKey, bucket, permissions)
			if err != nil {
				log.Fatalf("Failed to grant permission: %v", err)
			}

			fmt.Printf("Granted %s permissions on bucket %s to user %s\n", permissions, bucket, accessKey)
		},
	}

	grantCmd.Flags().String("access-key", "", "User access key")
	grantCmd.Flags().String("bucket", "", "Bucket pattern (e.g., 'my-bucket' or 'prefix-*')")
	grantCmd.Flags().String("permissions", "read,write", "Permissions (comma-separated: read,write,delete)")
	grantCmd.MarkFlagRequired("access-key")
	grantCmd.MarkFlagRequired("bucket")

	// Revoke permission command
	var revokeCmd = &cobra.Command{
		Use:   "revoke",
		Short: "Revoke bucket permission from a user",
		Run: func(cmd *cobra.Command, args []string) {
			db, um := setupDatabase(configFile, dbConfig)
			defer db.Close()

			accessKey, _ := cmd.Flags().GetString("access-key")
			bucket, _ := cmd.Flags().GetString("bucket")
			
			err := um.RevokeBucketPermission(accessKey, bucket)
			if err != nil {
				log.Fatalf("Failed to revoke permission: %v", err)
			}

			fmt.Printf("Revoked permissions on bucket %s from user %s\n", bucket, accessKey)
		},
	}

	revokeCmd.Flags().String("access-key", "", "User access key")
	revokeCmd.Flags().String("bucket", "", "Bucket pattern")
	revokeCmd.MarkFlagRequired("access-key")
	revokeCmd.MarkFlagRequired("bucket")

	rootCmd.AddCommand(createCmd, listCmd, disableCmd, enableCmd, grantCmd, revokeCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func setupDatabase(configFile string, dbConfig database.Config) (*database.DB, *database.UserManager) {
	// Try to load config from file first
	if configFile != "" {
		cfg, err := config.Load(configFile)
		if err == nil && cfg.Database.Enabled {
			dbConfig.ConnectionString = cfg.Database.ConnectionString
			dbConfig.Driver = cfg.Database.Driver
			dbConfig.MaxOpenConns = cfg.Database.MaxOpenConns
			dbConfig.MaxIdleConns = cfg.Database.MaxIdleConns
			dbConfig.ConnMaxLifetime = cfg.Database.ConnMaxLifetime
		}
	}

	// Ensure we have a connection string
	if dbConfig.ConnectionString == "" {
		log.Fatal("Database connection string is required. Use --db-connection or configure in config file")
	}

	db, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	return db, database.NewUserManager(db)
}