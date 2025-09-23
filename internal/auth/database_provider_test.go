package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"

	"github.com/einyx/foundation-storage-engine/internal/database"
)

// MockUserStore is a mock implementation of the UserStore interface
type MockUserStore struct {
	mock.Mock
}

func (m *MockUserStore) GetUserByAccessKey(accessKey string) (*database.User, error) {
	args := m.Called(accessKey)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*database.User), args.Error(1)
}

func (m *MockUserStore) UpdateLastLogin(userID int) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserStore) GetUserPermissions(userID int) ([]database.UserPermission, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]database.UserPermission), args.Error(1)
}

func (m *MockUserStore) CreateUser(user *database.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserStore) Close() error {
	return nil
}

func TestDatabaseProvider_AuthenticateBasic(t *testing.T) {
	// Create a mock database
	mockDB := &MockUserStore{}
	provider := &DatabaseProvider{
		db:    mockDB,
		cache: make(map[string]dbCacheEntry),
	}

	// Hash a test password
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)

	// Set up the mock to return a user
	testUser := &database.User{
		ID:        1,
		AccessKey: "test-access",
		SecretKey: string(hashedPassword),
		Email:     "test@example.com",
	}
	mockDB.On("GetUserByAccessKey", "test-access").Return(testUser, nil)
	mockDB.On("UpdateLastLogin", 1).Return(nil)

	// Create a request with basic auth
	req := httptest.NewRequest("GET", "/test", nil)
	req.SetBasicAuth("test-access", "test-secret")

	// Test authentication
	err := provider.Authenticate(req)
	assert.NoError(t, err)

	// Verify the user was cached
	assert.Len(t, provider.cache, 1)

	// Test with wrong password
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.SetBasicAuth("test-access", "wrong-password")
	err = provider.Authenticate(req2)
	assert.Error(t, err)
}

func TestDatabaseProvider_AuthenticateAWS(t *testing.T) {
	// Create a mock database
	mockDB := &MockUserStore{}
	provider := &DatabaseProvider{
		db:    mockDB,
		cache: make(map[string]dbCacheEntry),
	}

	// Set up the mock to return a user with plain text secret
	testUser := &database.User{
		ID:        1,
		AccessKey: "test-access",
		SecretKey: "test-secret", // Plain text for AWS signature
		Email:     "test@example.com",
	}
	mockDB.On("GetUserByAccessKey", "test-access").Return(testUser, nil)
	mockDB.On("UpdateLastLogin", 1).Return(nil)

	// Create a request with AWS auth header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "AWS test-access:signature")

	// Test authentication - since we have plain text secret, it will try to validate signature
	// For this test, we expect it to fail with signature mismatch (since we're using a fake signature)
	err := provider.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")

	// Test with unknown access key
	mockDB.On("GetUserByAccessKey", "unknown").Return(nil, nil)
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("Authorization", "AWS unknown:signature")
	err = provider.Authenticate(req2)
	assert.Error(t, err)
	
	// Test with bcrypt hashed secret (should skip signature validation)
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	hashedUser := &database.User{
		ID:        2,
		AccessKey: "hashed-access",
		SecretKey: string(hashedSecret),
		Email:     "hashed@example.com",
	}
	mockDB.On("GetUserByAccessKey", "hashed-access").Return(hashedUser, nil)
	mockDB.On("UpdateLastLogin", 2).Return(nil)
	
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.Header.Set("Authorization", "AWS hashed-access:any-signature")
	err = provider.Authenticate(req3)
	assert.NoError(t, err) // Should succeed because we skip signature validation for bcrypt hashes
}

func TestDatabaseProvider_GetSecretKey(t *testing.T) {
	// Create a mock database
	mockDB := &MockUserStore{}
	provider := &DatabaseProvider{
		db:    mockDB,
		cache: make(map[string]dbCacheEntry),
	}

	// Set up the mock
	testUser := &database.User{
		ID:        1,
		AccessKey: "test-access",
		SecretKey: "test-secret",
		Email:     "test@example.com",
	}
	mockDB.On("GetUserByAccessKey", "test-access").Return(testUser, nil)

	// Test getting secret key
	secret, err := provider.GetSecretKey("test-access")
	assert.NoError(t, err)
	assert.Equal(t, "test-secret", secret)

	// Test with unknown access key
	mockDB.On("GetUserByAccessKey", "unknown").Return(nil, nil)
	_, err = provider.GetSecretKey("unknown")
	assert.Error(t, err)
}

func TestDatabaseProvider_Caching(t *testing.T) {
	// Create a mock database
	mockDB := &MockUserStore{}
	provider := &DatabaseProvider{
		db:    mockDB,
		cache: make(map[string]dbCacheEntry),
	}

	// Set up the mock to be called only once
	testUser := &database.User{
		ID:        1,
		AccessKey: "test-access",
		SecretKey: "test-secret",
		Email:     "test@example.com",
	}
	mockDB.On("GetUserByAccessKey", "test-access").Return(testUser, nil).Once()

	// First call should hit the database
	user1, err := provider.getUserByAccessKey("test-access")
	assert.NoError(t, err)
	assert.NotNil(t, user1)

	// Second call should use cache
	user2, err := provider.getUserByAccessKey("test-access")
	assert.NoError(t, err)
	assert.NotNil(t, user2)
	assert.Equal(t, user1, user2)

	// Verify the database was only called once
	mockDB.AssertNumberOfCalls(t, "GetUserByAccessKey", 1)
}

func TestDatabaseProvider_CacheExpiry(t *testing.T) {
	// Create a mock database
	mockDB := &MockUserStore{}
	provider := &DatabaseProvider{
		db:    mockDB,
		cache: make(map[string]dbCacheEntry),
	}

	// Add an expired cache entry
	provider.cache["test-access"] = dbCacheEntry{
		user: &database.User{
			ID:        1,
			AccessKey: "test-access",
			SecretKey: "old-secret",
		},
		timestamp: time.Now().Add(-10 * time.Minute), // Expired
	}

	// Set up the mock to return updated user
	newUser := &database.User{
		ID:        1,
		AccessKey: "test-access",
		SecretKey: "new-secret",
		Email:     "test@example.com",
	}
	mockDB.On("GetUserByAccessKey", "test-access").Return(newUser, nil)

	// Should fetch from database due to expired cache
	user, err := provider.getUserByAccessKey("test-access")
	assert.NoError(t, err)
	assert.Equal(t, "new-secret", user.SecretKey)
}
