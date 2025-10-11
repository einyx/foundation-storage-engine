package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"github.com/sirupsen/logrus"
)

// GroupMapping represents a group to role mapping
type GroupMapping struct {
	GroupID     string   `json:"group_id"`
	GroupName   string   `json:"group_name"`
	Description string   `json:"description"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions,omitempty"`
}

// GroupMappingStore manages group mappings (in-memory for now)
type GroupMappingStore struct {
	mappings map[string]*GroupMapping
}

func NewGroupMappingStore() *GroupMappingStore {
	return &GroupMappingStore{
		mappings: make(map[string]*GroupMapping),
	}
}

// AdminHandlers provides admin endpoints for group/role management
type AdminHandlers struct {
	store *GroupMappingStore
	auth0 *Auth0Handler
}

func NewAdminHandlers(auth0 *Auth0Handler) *AdminHandlers {
	return &AdminHandlers{
		store: NewGroupMappingStore(),
		auth0: auth0,
	}
}

// ListGroupMappingsHandler returns all group mappings
func (h *AdminHandlers) ListGroupMappingsHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is admin
	if !h.isAdmin(r) {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	mappings := make([]*GroupMapping, 0)
	for _, mapping := range h.store.mappings {
		mappings = append(mappings, mapping)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mappings)
}

// CreateGroupMappingHandler creates a new group mapping
func (h *AdminHandlers) CreateGroupMappingHandler(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r) {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	var mapping GroupMapping
	if err := json.NewDecoder(r.Body).Decode(&mapping); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	h.store.mappings[mapping.GroupID] = &mapping

	logrus.WithFields(logrus.Fields{
		"group_id": mapping.GroupID,
		"group_name": mapping.GroupName,
		"roles": mapping.Roles,
	}).Info("Created group mapping")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(mapping)
}

// DeleteGroupMappingHandler deletes a group mapping
func (h *AdminHandlers) DeleteGroupMappingHandler(w http.ResponseWriter, r *http.Request) {
	if !h.isAdmin(r) {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	groupID := r.URL.Query().Get("group_id")
	if groupID == "" {
		http.Error(w, "Missing group_id parameter", http.StatusBadRequest)
		return
	}

	delete(h.store.mappings, groupID)

	logrus.WithField("group_id", groupID).Info("Deleted group mapping")
	w.WriteHeader(http.StatusNoContent)
}

// GetEffectiveRolesHandler returns effective roles for the current user
func (h *AdminHandlers) GetEffectiveRolesHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.auth0.store.Get(r, sessionName)
	if err != nil || session.Values["authenticated"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user's groups from session
	var groups []string
	if groupsStr, ok := session.Values["user_groups"].(string); ok && groupsStr != "" {
		groups = strings.Split(groupsStr, ",")
	}

	// Map groups to roles
	effectiveRoles := make(map[string]bool)
	effectivePermissions := make(map[string]bool)

	for _, group := range groups {
		if mapping, exists := h.store.mappings[group]; exists {
			for _, role := range mapping.Roles {
				effectiveRoles[role] = true
			}
			for _, perm := range mapping.Permissions {
				effectivePermissions[perm] = true
			}
		}
	}

	response := map[string]interface{}{
		"user": session.Values["user_email"],
		"groups": groups,
		"effective_roles": keys(effectiveRoles),
		"effective_permissions": keys(effectivePermissions),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper functions
func (h *AdminHandlers) isAdmin(r *http.Request) bool {
	session, err := h.auth0.store.Get(r, sessionName)
	if err != nil {
		return false
	}

	if rolesStr, ok := session.Values["user_roles"].(string); ok && rolesStr != "" {
		roles := strings.Split(rolesStr, ",")
		for _, role := range roles {
			if role == "admin" || role == "storage-admin" {
				return true
			}
		}
	}

	return false
}

func keys(m map[string]bool) []string {
	result := make([]string, 0, len(m))
	for k := range m {
		result = append(result, k)
	}
	return result
}