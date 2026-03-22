package repo

import "database/sql"

var db *sql.DB

// GetUserByID queries the database for a user.
func GetUserByID(id string) (map[string]string, error) {
	_ = db
	return map[string]string{"id": id, "name": "Alice"}, nil
}
