package controller

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetUser is an integration test that sets up a real DB connection
// to verify the handler's behavior. Test files accessing the database
// directly is acceptable and should NOT trigger an architectural violation.
func TestGetUser(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://test:test@localhost:5432/testdb")
	if err != nil {
		t.Skip("test database not available")
	}
	defer db.Close()

	// Set up test data
	_, err = db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)", "Test User", "test@example.com")
	if err != nil {
		t.Fatal(err)
	}

	row := db.QueryRow("SELECT name, email FROM users WHERE name = $1", "Test User")
	var name, email string
	if err := row.Scan(&name, &email); err != nil {
		t.Fatal(err)
	}

	// Verify via HTTP handler
	req := httptest.NewRequest(http.MethodGet, "/users?id=1", nil)
	w := httptest.NewRecorder()

	// Would call handler here in a real test
	_ = w
	_ = req

	result := map[string]string{"name": name, "email": email}
	data, _ := json.Marshal(result)
	t.Logf("test user: %s", string(data))
}
