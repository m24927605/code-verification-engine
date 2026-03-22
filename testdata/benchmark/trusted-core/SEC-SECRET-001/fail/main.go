package main

import (
	"fmt"
	"net/http"
)

const (
	// Hardcoded API key — this should be caught by the secret scanner.
	apiKey    = "sk-live-1234567890abcdef"
	dbPassword = "super_secret_password_123"
)

func handler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-API-Key") != apiKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "Hello, authenticated user!")
}

func main() {
	http.HandleFunc("/api/data", handler)
	http.ListenAndServe(":8080", nil)
}
