package main

import "os"

func authSecret() string {
	return os.Getenv("JWT_SECRET")
}

func main() {
	_ = authSecret()
}
