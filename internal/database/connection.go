package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/jmoiron/sqlx"
)

// DB represents the database connection
type DB struct {
	*sqlx.DB
}

// Ensure DB implements UserStore interface
var _ UserStore = (*DB)(nil)

// Config holds database configuration
type Config struct {
	Driver          string
	ConnectionString string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

// NewConnection creates a new database connection
func NewConnection(cfg Config) (*DB, error) {
	if cfg.Driver == "" {
		cfg.Driver = "postgres"
	}
	
	db, err := sqlx.Connect(cfg.Driver, cfg.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Set connection pool settings
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(25)
	}

	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(5)
	}

	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	} else {
		db.SetConnMaxLifetime(5 * time.Minute)
	}

	return &DB{db}, nil
}

// GetUserByAccessKey retrieves a user by their access key
func (db *DB) GetUserByAccessKey(accessKey string) (*User, error) {
	var user User
	query := `SELECT id, access_key, secret_key, email, created_at, last_login, active 
	          FROM users WHERE access_key = $1 AND active = true`
	
	err := db.Get(&user, query, accessKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	
	return &user, nil
}

// UpdateLastLogin updates the last login timestamp for a user
func (db *DB) UpdateLastLogin(userID int) error {
	query := `UPDATE users SET last_login = $1 WHERE id = $2`
	_, err := db.Exec(query, time.Now(), userID)
	return err
}

// GetUserPermissions retrieves permissions for a user
func (db *DB) GetUserPermissions(userID int) ([]UserPermission, error) {
	var permissions []UserPermission
	query := `SELECT id, user_id, bucket_pattern, permissions 
	          FROM user_permissions WHERE user_id = $1`
	
	err := db.Select(&permissions, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	
	return permissions, nil
}

// CreateUser creates a new user
func (db *DB) CreateUser(user *User) error {
	query := `INSERT INTO users (access_key, secret_key, email, created_at, active) 
	          VALUES ($1, $2, $3, $4, $5) RETURNING id`
	
	err := db.Get(&user.ID, query, user.AccessKey, user.SecretKey, user.Email, time.Now(), true)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	
	return nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.DB.Close()
}