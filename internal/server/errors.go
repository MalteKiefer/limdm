package server

import (
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgconn"
)

// userError is a rejected request; its message is safe to show the client.
type userError struct {
	Status int
	Msg    string
}

func (e *userError) Error() string { return e.Msg }

// invalid marks a validation error.
func invalid(err error) error { return &userError{http.StatusUnprocessableEntity, err.Error()} }

// errStatus maps an error of a shared action to a status and a safe
// message; 0 is an internal error.
func errStatus(err error) (int, string) {
	var ue *userError
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &ue):
		return ue.Status, ue.Msg
	case isUnique(err):
		return http.StatusConflict, "the name is already in use"
	case errors.As(err, &pe) && pe.Code == "23503":
		return http.StatusConflict, "a referenced object does not exist or is still in use"
	}
	return 0, ""
}

// failUser answers a console request with the error's status, or 500.
func (s *Server) failUser(w http.ResponseWriter, err error) {
	if code, msg := errStatus(err); code != 0 {
		http.Error(w, msg, code)
		return
	}
	s.fail(w, err)
}
