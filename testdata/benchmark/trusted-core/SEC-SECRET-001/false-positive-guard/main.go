package main

import (
	"fmt"
	"os"
)

// Configuration with placeholder values that should NOT trigger secret detection.
var (
	placeholder = "REPLACE_ME"
	example     = "your-api-key-here"
	template    = "<INSERT_TOKEN>"
	empty       = ""
	envRef      = os.Getenv("SECRET_KEY")
)

func main() {
	fmt.Println("App configured with placeholders")
	fmt.Println("API Key:", envRef)
}
