package database

import (
	"time"
)

// User represents a user in the database
type User struct {
	ID         int       `db:"id"`
	AccessKey  string    `db:"access_key"`
	SecretKey  string    `db:"secret_key"`
	Email      string    `db:"email"`
	CreatedAt  time.Time `db:"created_at"`
	LastLogin  *time.Time `db:"last_login"`
	Active     bool      `db:"active"`
}

// UserPermission represents bucket-level permissions for a user
type UserPermission struct {
	ID            int    `db:"id"`
	UserID        int    `db:"user_id"`
	BucketPattern string `db:"bucket_pattern"`
	Permissions   string `db:"permissions"` // comma-separated: read,write,delete
}