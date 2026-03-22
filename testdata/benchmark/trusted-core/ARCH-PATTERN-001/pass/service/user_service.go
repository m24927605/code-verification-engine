package service

// UserRepo defines the repository interface for user operations.
type UserRepo interface {
	FindByID(id string) (map[string]string, error)
	Save(user map[string]string) error
}

// UserService handles business logic, delegating data access to the repository.
type UserService struct {
	repo UserRepo
}

// NewUserService creates a new UserService with the given repository.
func NewUserService(repo UserRepo) *UserService {
	return &UserService{repo: repo}
}

// GetUser retrieves a user by ID.
func (s *UserService) GetUser(id string) (map[string]string, error) {
	return s.repo.FindByID(id)
}
