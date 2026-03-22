package main

import (
	"fmt"
	"os"
)

// Application that uses environment variables for configuration.
// The .env.example file provides a template — it is safe to commit.
func main() {
	apiKey := os.Getenv("API_KEY")
	dbURL := os.Getenv("DATABASE_URL")
	fmt.Printf("Connecting with API key length=%d to %s\n", len(apiKey), dbURL)
}
