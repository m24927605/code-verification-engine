package controller

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

// UserHandler directly accesses the database — this violates layering rules.
type UserHandler struct {
	db *sql.DB
}

// NewUserHandler creates a handler with direct database access.
func NewUserHandler(db *sql.DB) *UserHandler {
	return &UserHandler{db: db}
}

// GetUser handles GET /users/:id by querying the database directly.
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	row := h.db.QueryRow("SELECT name, email FROM users WHERE id = $1", id)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"name": name, "email": email})
}
