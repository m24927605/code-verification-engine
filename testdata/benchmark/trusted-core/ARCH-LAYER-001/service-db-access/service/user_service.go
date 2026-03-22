package service

import "database/sql"

// UserService handles business logic and has legitimate DB access.
// The ARCH-LAYER-001 rule only prohibits direct DB access from controllers,
// not from service-layer files.
type UserService struct {
	db *sql.DB
}

// NewUserService creates a new user service with a database connection.
func NewUserService(db *sql.DB) *UserService {
	return &UserService{db: db}
}

// GetUserByID retrieves a user by their ID.
// Service-layer DB access is architecturally acceptable.
func (s *UserService) GetUserByID(id string) (map[string]string, error) {
	row := s.db.QueryRow("SELECT name, email FROM users WHERE id = $1", id)
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		return nil, err
	}
	return map[string]string{"name": name, "email": email}, nil
}

// CreateUser saves a new user to the database.
func (s *UserService) CreateUser(name, email string) error {
	_, err := s.db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)", name, email)
	return err
}
