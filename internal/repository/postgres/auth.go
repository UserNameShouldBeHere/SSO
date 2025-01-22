package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type PgxPool interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	Close()
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type AuthStorage struct {
	pool PgxPool
}

func NewAuthStorage(pool PgxPool) (*AuthStorage, error) {
	return &AuthStorage{
		pool: pool,
	}, nil
}

func (authStorage *AuthStorage) CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) error {
	hasUser, err := authStorage.hasUser(ctx, userCreds.Email)
	if err != nil {
		return fmt.Errorf("%w (postgres.CreateUser)", customErrors.ErrInternal)
	}
	if hasUser {
		return fmt.Errorf("%w (postgres.CreateUser)", customErrors.ErrAlreadyExists)
	}

	_, err = authStorage.pool.Exec(ctx, `
		insert into users(name, email, password) values ($1, $2, $3);
	`, userCreds.Name, userCreds.Email, userCreds.Password)
	if err != nil {
		return fmt.Errorf("%w (postgres.CreateUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return nil
}

func (authStorage *AuthStorage) GetPassword(ctx context.Context, email string) (string, error) {
	var password string

	err := authStorage.pool.QueryRow(ctx, `
		select password
		from users
		where email = $1;
	`, email).Scan(&password)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("%w (postgres.GetPassword): %w", customErrors.ErrDoesNotExist, err)
		}

		return "", fmt.Errorf("%w (postgres.GetPassword): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return password, nil
}

func (authStorage *AuthStorage) hasUser(ctx context.Context, email string) (bool, error) {
	err := authStorage.pool.QueryRow(ctx, `
		select
		from users
		where email = $1;
	`, email).Scan()
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("%w (postgres.hasUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return true, nil
}
