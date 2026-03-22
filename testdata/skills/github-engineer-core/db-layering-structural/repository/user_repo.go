package repository

import "database/sql"

type UserRepository struct {
	db *sql.DB
}

func (r *UserRepository) FindByID(id int) (string, error) {
	var name string
	err := r.db.QueryRow("SELECT name FROM users WHERE id = ?", id).Scan(&name)
	return name, err
}
