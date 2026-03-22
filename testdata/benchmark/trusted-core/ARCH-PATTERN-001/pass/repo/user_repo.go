package repo

import "database/sql"

// UserRepository encapsulates all database access for user operations.
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new repository with the given database connection.
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// FindByID retrieves a user by their ID.
func (r *UserRepository) FindByID(id string) (map[string]string, error) {
	row := r.db.QueryRow("SELECT name, email FROM users WHERE id = $1", id)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		return nil, err
	}
	return map[string]string{"name": name, "email": email}, nil
}

// Save persists a user to the database.
func (r *UserRepository) Save(user map[string]string) error {
	_, err := r.db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)",
		user["name"], user["email"])
	return err
}
