package main

import (
	"net/http"
)

func main() {
	http.HandleFunc("/users", handleUsers)
	http.ListenAndServe(":8080", nil)
}

func handleUsers(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
