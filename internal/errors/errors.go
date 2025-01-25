package errors

import (
	"errors"

	"google.golang.org/grpc/codes"
)

// common and api errors
var (
	ErrDataNotValid             = errors.New("invalid data")
	ErrIncorrectEmailOrPassword = errors.New("incorrect email or password")
)

func GetGrpcStatus(err error) codes.Code {
	switch {
	case errors.Is(err, ErrIncorrectEmailOrPassword),
		errors.Is(err, ErrDataNotValid):
		return codes.InvalidArgument
	case errors.Is(err, ErrDoesNotExist):
		return codes.NotFound
	case errors.Is(err, ErrAlreadyExists):
		return codes.AlreadyExists
	case errors.Is(err, ErrPermissionsDenied):
		return codes.PermissionDenied
	case errors.Is(err, ErrFailedToRollback),
		errors.Is(err, ErrFailedToExecuteQuery),
		errors.Is(err, ErrFailedToCreateToken),
		errors.Is(err, ErrFailedToExecuteMethod),
		errors.Is(err, ErrFailedToGenJWTKey),
		errors.Is(err, ErrFailedToBeginTx),
		errors.Is(err, ErrFailedToRollbackTx),
		errors.Is(err, ErrFailedToCommitTx),
		errors.Is(err, ErrInternal):
		return codes.Internal
	case errors.Is(err, ErrUnauthenticated),
		errors.Is(err, ErrFailedToSignToken):
		return codes.Unauthenticated
	default:
		return codes.Internal
	}
}
