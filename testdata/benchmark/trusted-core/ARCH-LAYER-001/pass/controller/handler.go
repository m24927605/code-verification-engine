package controller

import (
	"encoding/json"
	"net/http"
)

// UserService defines the service interface used by the handler.
type UserService interface {
	GetUser(id string) (map[string]string, error)
	CreateUser(name, email string) error
}

// UserHandler handles HTTP requests for user operations.
type UserHandler struct {
	service UserService
}

// NewUserHandler creates a handler with the given service dependency.
func NewUserHandler(svc UserService) *UserHandler {
	return &UserHandler{service: svc}
}

// GetUser handles GET /users/:id requests.
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	user, err := h.service.GetUser(id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}
