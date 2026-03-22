package main

import (
	"fmt"
	"os"
)

// Application that loads config. The .env file in this directory is the violation.
func main() {
	apiKey := os.Getenv("API_KEY")
	fmt.Println("Starting with key:", apiKey)
}
