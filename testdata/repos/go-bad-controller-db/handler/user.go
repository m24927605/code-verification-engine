package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

var db *sql.DB

// GetUser directly accesses the database from the handler layer.
func GetUser(w http.ResponseWriter, r *http.Request) {
	row := db.QueryRow("SELECT id, name FROM users WHERE id = ?", "123")
	var id, name string
	row.Scan(&id, &name)
	json.NewEncoder(w).Encode(map[string]string{"id": id, "name": name})
}
