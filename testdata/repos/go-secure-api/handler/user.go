package handler

import (
	"encoding/json"
	"net/http"

	"example.com/go-secure-api/service"
)

// GetUser handles GET /users/:id.
func GetUser(w http.ResponseWriter, r *http.Request) {
	user, err := service.FindUser("123")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(user)
}
