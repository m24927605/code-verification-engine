package repo

import "database/sql"

// UserRepository handles all database operations for users.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// FindByID retrieves a user by their ID from the database.
func (r *UserRepository) FindByID(id string) (map[string]string, error) {
	row := r.db.QueryRow("SELECT name, email FROM users WHERE id = $1", id)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		return nil, err
	}
	return map[string]string{"name": name, "email": email}, nil
}
