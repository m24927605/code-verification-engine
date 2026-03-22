package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// HealthHandler provides health check endpoints.
// It resides in handler/ but performs no database operations.
type HealthHandler struct {
	startTime time.Time
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{startTime: time.Now()}
}

// Check handles GET /health — returns service uptime and status.
// No database access here; should NOT trigger repository encapsulation rule.
func (h *HealthHandler) Check(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(h.startTime).String()
	response := map[string]string{
		"status": "ok",
		"uptime": uptime,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Ready handles GET /ready — checks if the service is ready to accept requests.
func (h *HealthHandler) Ready(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ready": true}`))
}
