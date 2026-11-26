package server

import (
	"context"
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

// fieldError is a validation error (422) of one field of the request; the
// admin API names it in the problem details (errors: [{field, message}]).
type fieldError struct {
	Field string
	Msg   string
}

func (e *fieldError) Error() string { return e.Msg }

// invalid marks a validation error of field.
func invalid(field string, err error) error { return &fieldError{field, err.Error()} }

// errStatus maps an error of a shared action to a status and a safe
// message; 0 is an internal error.
func errStatus(err error) (int, string) {
	var ue *userError
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &ue):
		return ue.Status, ue.Msg
	case errors.As(err, new(*fieldError)):
		return http.StatusUnprocessableEntity, err.Error()
	case isUnique(err):
		return http.StatusConflict, "the name is already in use"
	case errors.As(err, &pe) && pe.Code == "23503":
		return http.StatusConflict, "a referenced object does not exist or is still in use"
	}
	return 0, ""
}

// overloaded reports an error of a busy database rather than of the request:
// a lock or statement timeout, a serialization failure or deadlock, too many
// connections, or no free pool connection in time. Clients retry these.
func overloaded(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "55P03", "57014", "40001", "40P01", "53300":
			return true
		}
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// failUser answers a console request with the error page for the error's
// status, or 500.
func (s *Server) failUser(w http.ResponseWriter, r *http.Request, sess session, err error) {
	if code, msg := errStatus(err); code != 0 {
		s.errorPage(w, r, sess, code, msg)
		return
	}
	s.fail(w, err)
}
