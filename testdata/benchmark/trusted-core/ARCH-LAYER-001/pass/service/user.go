package service

// UserRepository defines the data access interface.
type UserRepository interface {
	FindByID(id string) (map[string]string, error)
	Save(user map[string]string) error
}

// UserService handles business logic for user operations.
type UserService struct {
	repo UserRepository
}

// NewUserService creates a new user service with the given repository.
func NewUserService(repo UserRepository) *UserService {
	return &UserService{repo: repo}
}

// GetUser retrieves a user by ID through the repository.
func (s *UserService) GetUser(id string) (map[string]string, error) {
	return s.repo.FindByID(id)
}

// CreateUser saves a new user through the repository.
func (s *UserService) CreateUser(name, email string) error {
	user := map[string]string{"name": name, "email": email}
	return s.repo.Save(user)
}
