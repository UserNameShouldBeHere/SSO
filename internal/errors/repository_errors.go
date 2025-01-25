package errors

import "errors"

var (
	ErrDoesNotExist      = errors.New("doesn't exist")
	ErrPermissionsDenied = errors.New("permissions denied")

	// postgres
	ErrFailedToRollback     = errors.New("failed to rollback transaction")
	ErrFailedToExecuteQuery = errors.New("failed to execute query")
	ErrAlreadyExists        = errors.New("already exists")
	ErrFailedToBeginTx      = errors.New("failed to begin transaction")
	ErrFailedToRollbackTx   = errors.New("failed to rollback transaction")
	ErrFailedToCommitTx     = errors.New("failed to commit transaction")

	// redis
	ErrFailedToCreateToken   = errors.New("failed to create token")
	ErrFailedToExecuteMethod = errors.New("failed to execute method")
	ErrFailedToGenJWTKey     = errors.New("failed to generate key")
	ErrFailedToSignToken     = errors.New("failed to sign token")
	ErrUnauthenticated       = errors.New("unauthenticated")
)
