package main

import (
	"fmt"
	"os"
)

func main() {
	apiKey := os.Getenv("API_KEY")
	dbURL := os.Getenv("DATABASE_URL")
	fmt.Println("Starting with config from environment", apiKey != "", dbURL != "")
}
