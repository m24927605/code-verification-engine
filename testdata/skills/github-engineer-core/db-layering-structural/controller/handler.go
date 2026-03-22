package controller

import (
	"fmt"
	"net/http"
)

type UserHandler struct{}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "user data")
}
