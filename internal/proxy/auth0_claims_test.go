package proxy

import (
	"testing"

	"github.com/einyx/foundation-storage-engine/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestAuth0Handler_mapDirectoryRoleIDs(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name     string
		wids     []interface{}
		expected []string
		description string
	}{
		{
			name: "global_administrator",
			wids: []interface{}{"62e90394-69f5-4237-9190-012177145e10"},
			expected: []string{"admin", "global-admin"},
			description: "Global Administrator role should map to admin roles",
		},
		{
			name: "privileged_role_admin",
			wids: []interface{}{"e8611ab8-c189-46e8-94e1-60213ab1f814"},
			expected: []string{"admin", "privileged-role-admin"},
			description: "Privileged Role Administrator should map to admin roles",
		},
		{
			name: "cloud_app_admin",
			wids: []interface{}{"158c047a-c907-4556-b7ef-446551a6b5f7"},
			expected: []string{"admin", "cloud-app-admin"},
			description: "Cloud Application Administrator should map to admin roles",
		},
		{
			name: "privileged_auth_admin",
			wids: []interface{}{"7be44c8a-adaf-4e2a-84d6-ab2649e08a13"},
			expected: []string{"admin", "privileged-auth-admin"},
			description: "Privileged Authentication Administrator should map to admin roles",
		},
		{
			name: "conditional_access_admin",
			wids: []interface{}{"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"},
			expected: []string{"admin", "conditional-access-admin"},
			description: "Conditional Access Administrator should map to admin roles",
		},
		{
			name: "multiple_admin_roles",
			wids: []interface{}{
				"62e90394-69f5-4237-9190-012177145e10", // Global Administrator
				"e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
			},
			expected: []string{"admin", "global-admin", "admin", "privileged-role-admin"},
			description: "Multiple admin roles should all be mapped",
		},
		{
			name: "unknown_role_id",
			wids: []interface{}{"unknown-role-id-12345"},
			expected: []string(nil),
			description: "Unknown role IDs should return nil slice",
		},
		{
			name: "mixed_known_unknown",
			wids: []interface{}{
				"62e90394-69f5-4237-9190-012177145e10", // Global Administrator
				"unknown-role-id-12345",                 // Unknown
			},
			expected: []string{"admin", "global-admin"},
			description: "Mixed known/unknown roles should map only known ones",
		},
		{
			name: "empty_wids",
			wids: []interface{}{},
			expected: []string(nil),
			description: "Empty WIDs should return nil slice",
		},
		{
			name: "non_string_wids",
			wids: []interface{}{123, true, nil},
			expected: []string(nil),
			description: "Non-string WIDs should be ignored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.mapDirectoryRoleIDs(tt.wids)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestAuth0Handler_processDirectoryRoles(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name           string
		wids           interface{}
		initialGroups  interface{}
		initialRoles   interface{}
		expectedGroups interface{}
		expectedRoles  interface{}
		description    string
	}{
		{
			name: "wids_as_groups_when_no_groups",
			wids: []interface{}{"62e90394-69f5-4237-9190-012177145e10"},
			initialGroups: nil,
			initialRoles:  nil,
			expectedGroups: []interface{}{"62e90394-69f5-4237-9190-012177145e10"},
			expectedRoles:  []string{"admin", "global-admin"},
			description: "WIDs should be used as groups when no other groups found",
		},
		{
			name: "wids_not_overriding_existing_groups",
			wids: []interface{}{"62e90394-69f5-4237-9190-012177145e10"},
			initialGroups: []string{"existing-group"},
			initialRoles:  nil,
			expectedGroups: []string{"existing-group"},
			expectedRoles:  []string{"admin", "global-admin"},
			description: "WIDs should not override existing groups",
		},
		{
			name: "wids_not_overriding_existing_roles",
			wids: []interface{}{"62e90394-69f5-4237-9190-012177145e10"},
			initialGroups: nil,
			initialRoles:  []string{"existing-role"},
			expectedGroups: []interface{}{"62e90394-69f5-4237-9190-012177145e10"},
			expectedRoles:  []string{"existing-role"},
			description: "WIDs should not override existing roles",
		},
		{
			name: "non_array_wids",
			wids: "not-an-array",
			initialGroups: nil,
			initialRoles:  nil,
			expectedGroups: "not-an-array",
			expectedRoles:  nil,
			description: "Non-array WIDs should be stored as groups but not processed as roles",
		},
		{
			name: "empty_wids_array",
			wids: []interface{}{},
			initialGroups: nil,
			initialRoles:  nil,
			expectedGroups: []interface{}{},
			expectedRoles:  nil,
			description: "Empty WIDs array should be handled gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := tt.initialGroups
			roles := tt.initialRoles

			handler.processDirectoryRoles(tt.wids, &groups, &roles)

			assert.Equal(t, tt.expectedGroups, groups, tt.description+" - groups")
			assert.Equal(t, tt.expectedRoles, roles, tt.description+" - roles")
		})
	}
}

func TestAuth0Handler_extractGroupsFromClaims(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name        string
		claims      map[string]interface{}
		expected    interface{}
		description string
	}{
		{
			name: "foundation_groups_claim",
			claims: map[string]interface{}{
				"https://foundation.dev/groups": []string{"group1", "group2"},
			},
			expected: []string{"group1", "group2"},
			description: "Should extract from foundation.dev groups claim",
		},
		{
			name: "standard_groups_claim",
			claims: map[string]interface{}{
				"groups": []string{"std-group1", "std-group2"},
			},
			expected: []string{"std-group1", "std-group2"},
			description: "Should extract from standard groups claim",
		},
		{
			name: "microsoft_groups_claim",
			claims: map[string]interface{}{
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups": []string{"ms-group1"},
			},
			expected: []string{"ms-group1"},
			description: "Should extract from Microsoft groups claim",
		},
		{
			name: "claim_names",
			claims: map[string]interface{}{
				"_claim_names": []string{"claim1", "claim2"},
			},
			expected: []string{"claim1", "claim2"},
			description: "Should extract from _claim_names",
		},
		{
			name: "groupids_claim",
			claims: map[string]interface{}{
				"groupids": []string{"id1", "id2"},
			},
			expected: []string{"id1", "id2"},
			description: "Should extract from groupids claim",
		},
		{
			name: "roles_as_groups",
			claims: map[string]interface{}{
				"roles": []string{"role1", "role2"},
			},
			expected: []string{"role1", "role2"},
			description: "Should extract from roles claim when used as groups",
		},
		{
			name: "microsoft_roles_claim",
			claims: map[string]interface{}{
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": []string{"ms-role1"},
			},
			expected: []string{"ms-role1"},
			description: "Should extract from Microsoft roles claim",
		},
		{
			name: "wids_claim",
			claims: map[string]interface{}{
				"wids": []string{"wid1", "wid2"},
			},
			expected: []string{"wid1", "wid2"},
			description: "Should extract from wids claim",
		},
		{
			name: "priority_foundation_over_standard",
			claims: map[string]interface{}{
				"https://foundation.dev/groups": []string{"foundation-group"},
				"groups": []string{"standard-group"},
			},
			expected: []string{"foundation-group"},
			description: "Should prioritize foundation.dev groups over standard groups",
		},
		{
			name: "no_groups_found",
			claims: map[string]interface{}{
				"sub": "user123",
				"email": "user@example.com",
			},
			expected: nil,
			description: "Should return nil when no groups found",
		},
		{
			name: "empty_claims",
			claims: map[string]interface{}{},
			expected: nil,
			description: "Should return nil for empty claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.extractGroupsFromClaims(tt.claims)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestAuth0Handler_extractRolesFromClaims(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	tests := []struct {
		name        string
		claims      map[string]interface{}
		expected    interface{}
		description string
	}{
		{
			name: "foundation_roles_claim",
			claims: map[string]interface{}{
				"https://foundation.dev/roles": []string{"admin", "user"},
			},
			expected: []string{"admin", "user"},
			description: "Should extract from foundation.dev roles claim",
		},
		{
			name: "standard_roles_claim",
			claims: map[string]interface{}{
				"roles": []string{"role1", "role2"},
			},
			expected: []string{"role1", "role2"},
			description: "Should extract from standard roles claim",
		},
		{
			name: "microsoft_roles_claim",
			claims: map[string]interface{}{
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": []string{"ms-role1"},
			},
			expected: []string{"ms-role1"},
			description: "Should extract from Microsoft roles claim",
		},
		{
			name: "priority_foundation_over_standard",
			claims: map[string]interface{}{
				"https://foundation.dev/roles": []string{"foundation-role"},
				"roles": []string{"standard-role"},
			},
			expected: []string{"foundation-role"},
			description: "Should prioritize foundation.dev roles over standard roles",
		},
		{
			name: "priority_standard_over_microsoft",
			claims: map[string]interface{}{
				"roles": []string{"standard-role"},
				"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": []string{"ms-role"},
			},
			expected: []string{"standard-role"},
			description: "Should prioritize standard roles over Microsoft roles",
		},
		{
			name: "no_roles_found",
			claims: map[string]interface{}{
				"sub": "user123",
				"email": "user@example.com",
			},
			expected: nil,
			description: "Should return nil when no roles found",
		},
		{
			name: "empty_claims",
			claims: map[string]interface{}{},
			expected: nil,
			description: "Should return nil for empty claims",
		},
		{
			name: "null_roles_value",
			claims: map[string]interface{}{
				"roles": nil,
			},
			expected: nil,
			description: "Should return nil for null roles value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.extractRolesFromClaims(tt.claims)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestAuth0Handler_createFallbackUserInfo(t *testing.T) {
	cfg := &config.Auth0Config{
		Enabled:    true,
		SessionKey: "test-session-key-32-characters!",
	}
	handler := NewAuth0Handler(cfg)

	result := handler.createFallbackUserInfo()

	expected := map[string]interface{}{
		"sub":    "unknown_user",
		"email":  "unknown@example.com",
		"name":   "Unknown User",
		"roles":  []string{},
		"groups": []string{},
	}

	assert.Equal(t, expected, result)
	assert.NotNil(t, result["roles"])
	assert.NotNil(t, result["groups"])
	assert.IsType(t, []string{}, result["roles"])
	assert.IsType(t, []string{}, result["groups"])
}

func TestUserClaims_HasRole(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		testRole string
		expected bool
		description string
	}{
		{
			name:     "has_admin_role",
			roles:    []string{"admin", "user"},
			testRole: "admin",
			expected: true,
			description: "Should return true when user has the role",
		},
		{
			name:     "has_user_role",
			roles:    []string{"admin", "user"},
			testRole: "user",
			expected: true,
			description: "Should return true when user has the role",
		},
		{
			name:     "does_not_have_role",
			roles:    []string{"admin", "user"},
			testRole: "guest",
			expected: false,
			description: "Should return false when user does not have the role",
		},
		{
			name:     "empty_roles",
			roles:    []string{},
			testRole: "admin",
			expected: false,
			description: "Should return false when user has no roles",
		},
		{
			name:     "nil_roles",
			roles:    nil,
			testRole: "admin",
			expected: false,
			description: "Should return false when roles is nil",
		},
		{
			name:     "case_sensitive",
			roles:    []string{"Admin", "User"},
			testRole: "admin",
			expected: false,
			description: "Should be case sensitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &UserClaims{
				Roles: tt.roles,
			}
			result := claims.HasRole(tt.testRole)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestUserClaims_IsAdmin(t *testing.T) {
	tests := []struct {
		name     string
		roles    []string
		expected bool
		description string
	}{
		{
			name:     "admin_role",
			roles:    []string{"admin", "user"},
			expected: true,
			description: "Should return true for admin role",
		},
		{
			name:     "storage_admin_role",
			roles:    []string{"storage-admin", "user"},
			expected: true,
			description: "Should return true for storage-admin role",
		},
		{
			name:     "super_admin_role",
			roles:    []string{"super-admin", "user"},
			expected: true,
			description: "Should return true for super-admin role",
		},
		{
			name:     "multiple_admin_roles",
			roles:    []string{"admin", "storage-admin", "super-admin"},
			expected: true,
			description: "Should return true when user has multiple admin roles",
		},
		{
			name:     "non_admin_roles",
			roles:    []string{"user", "guest", "viewer"},
			expected: false,
			description: "Should return false when user has no admin roles",
		},
		{
			name:     "empty_roles",
			roles:    []string{},
			expected: false,
			description: "Should return false when user has no roles",
		},
		{
			name:     "nil_roles",
			roles:    nil,
			expected: false,
			description: "Should return false when roles is nil",
		},
		{
			name:     "case_sensitive_admin",
			roles:    []string{"Admin", "ADMIN"},
			expected: false,
			description: "Should be case sensitive for admin roles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &UserClaims{
				Roles: tt.roles,
			}
			result := claims.IsAdmin()
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}