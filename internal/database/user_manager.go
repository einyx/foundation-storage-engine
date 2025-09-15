package database

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// UserManager provides user management functionality
type UserManager struct {
	db *DB
}

// NewUserManager creates a new user manager
func NewUserManager(db *DB) *UserManager {
	return &UserManager{db: db}
}

// CreateUser creates a new user with the given email and password
func (um *UserManager) CreateUser(email, password string) (*User, error) {
	// Generate access key
	accessKey, err := generateAccessKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access key: %w", err)
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &User{
		Email:     email,
		AccessKey: accessKey,
		SecretKey: string(hashedPassword),
		Active:    true,
	}

	if err := um.db.CreateUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// CreateUserWithKeys creates a new user with specific access/secret keys
func (um *UserManager) CreateUserWithKeys(email, accessKey, secretKey string) (*User, error) {
	// Hash the secret key
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(secretKey), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash secret key: %w", err)
	}

	user := &User{
		Email:     email,
		AccessKey: accessKey,
		SecretKey: string(hashedSecret),
		Active:    true,
	}

	if err := um.db.CreateUser(user); err != nil {
		return nil, err
	}

	return user, nil
}

// AuthenticateUser verifies user credentials
func (um *UserManager) AuthenticateUser(accessKey, secretKey string) (*User, error) {
	user, err := um.db.GetUserByAccessKey(accessKey)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify secret key
	err = bcrypt.CompareHashAndPassword([]byte(user.SecretKey), []byte(secretKey))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	go func() {
		_ = um.db.UpdateLastLogin(user.ID)
	}()

	return user, nil
}

// DisableUser disables a user account
func (um *UserManager) DisableUser(accessKey string) error {
	query := `UPDATE users SET active = false WHERE access_key = $1`
	_, err := um.db.Exec(query, accessKey)
	return err
}

// EnableUser enables a user account
func (um *UserManager) EnableUser(accessKey string) error {
	query := `UPDATE users SET active = true WHERE access_key = $1`
	_, err := um.db.Exec(query, accessKey)
	return err
}

// UpdateUserPassword updates a user's password
func (um *UserManager) UpdateUserPassword(accessKey, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	query := `UPDATE users SET secret_key = $1 WHERE access_key = $2`
	_, err = um.db.Exec(query, string(hashedPassword), accessKey)
	return err
}

// GrantBucketPermission grants permissions to a user for a bucket pattern
func (um *UserManager) GrantBucketPermission(accessKey, bucketPattern, permissions string) error {
	// First get the user
	user, err := um.db.GetUserByAccessKey(accessKey)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	query := `INSERT INTO user_permissions (user_id, bucket_pattern, permissions) 
	          VALUES ($1, $2, $3)`
	_, err = um.db.Exec(query, user.ID, bucketPattern, permissions)
	return err
}

// RevokeBucketPermission revokes permissions from a user for a bucket pattern
func (um *UserManager) RevokeBucketPermission(accessKey, bucketPattern string) error {
	// First get the user
	user, err := um.db.GetUserByAccessKey(accessKey)
	if err != nil {
		return err
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	query := `DELETE FROM user_permissions WHERE user_id = $1 AND bucket_pattern = $2`
	_, err = um.db.Exec(query, user.ID, bucketPattern)
	return err
}

// ListUsers lists all users
func (um *UserManager) ListUsers() ([]User, error) {
	var users []User
	query := `SELECT id, access_key, email, created_at, last_login, active FROM users ORDER BY created_at DESC`
	err := um.db.Select(&users, query)
	return users, err
}

// generateAccessKey generates a random access key
func generateAccessKey() (string, error) {
	bytes := make([]byte, 20)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	// Create AWS-style access key
	key := base64.URLEncoding.EncodeToString(bytes)
	key = strings.ReplaceAll(key, "-", "")
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ToUpper(key)
	
	if len(key) > 20 {
		key = key[:20]
	}
	
	return key, nil
}