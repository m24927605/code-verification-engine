package service

import "example.com/go-secure-api/repo"

// FindUser retrieves a user through the repository layer.
func FindUser(id string) (map[string]string, error) {
	return repo.GetUserByID(id)
}
