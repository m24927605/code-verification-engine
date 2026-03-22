package main

import (
	"fmt"
	"os"
)

// Application that properly uses environment variables without .env files.
func main() {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	fmt.Printf("Connecting to database at %s:%s\n", dbHost, dbPort)
}
