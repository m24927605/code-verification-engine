package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

// UserHandler performs database operations directly — violates repository encapsulation.
type UserHandler struct {
	db *sql.DB
}

// NewUserHandler creates a handler with direct DB access.
func NewUserHandler(db *sql.DB) *UserHandler {
	return &UserHandler{db: db}
}

// ListUsers queries the database directly from the handler layer.
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, name, email FROM users")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []map[string]string
	for rows.Next() {
		var id, name, email string
		rows.Scan(&id, &name, &email)
		users = append(users, map[string]string{"id": id, "name": name, "email": email})
	}
	json.NewEncoder(w).Encode(users)
}
