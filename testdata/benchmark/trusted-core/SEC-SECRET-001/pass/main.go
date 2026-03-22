package main

import (
	"fmt"
	"os"
)

// Config holds application configuration loaded from environment variables.
type Config struct {
	DatabaseURL string
	APIKey      string
	Port        string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() *Config {
	return &Config{
		DatabaseURL: os.Getenv("DATABASE_URL"),
		APIKey:      os.Getenv("API_KEY"),
		Port:        os.Getenv("PORT"),
	}
}

func main() {
	cfg := LoadConfig()
	fmt.Printf("Starting server on port %s\n", cfg.Port)
}
