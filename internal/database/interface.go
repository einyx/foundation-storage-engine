package database

// UserStore defines the interface for user-related database operations
type UserStore interface {
	GetUserByAccessKey(accessKey string) (*User, error)
	UpdateLastLogin(userID int) error
	GetUserPermissions(userID int) ([]UserPermission, error)
	CreateUser(user *User) error
	Close() error
}