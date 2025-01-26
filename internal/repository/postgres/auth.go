package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

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
	CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error)
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

func (authStorage *AuthStorage) GetPermissionsLevel(ctx context.Context, email string) (uint32, error) {
	var permissionsLevel uint32

	err := authStorage.pool.QueryRow(ctx, `
		select permissions_level
		from users
		where email = $1;
	`, email).Scan(&permissionsLevel)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("%w (postgres.GetPermissionsLevel): %w", customErrors.ErrDoesNotExist, err)
		}

		return 0, fmt.Errorf("%w (postgres.GetPermissionsLevel): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return permissionsLevel, nil
}

func (authStorage *AuthStorage) GetUser(ctx context.Context, email string) (domain.User, error) {
	var user domain.User

	err := authStorage.pool.QueryRow(ctx, `
		select uuid, name, email, permissions_level, registered_at
		from users
		where email = $1;
	`, email).Scan(
		&user.Uuid,
		&user.Name,
		&user.Email,
		&user.PermissionsLevel,
		&user.RegisteredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, fmt.Errorf("%w (postgres.GetPassword): %w", customErrors.ErrDoesNotExist, err)
		}

		return domain.User{}, fmt.Errorf("%w (postgres.GetPassword): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return user, nil
}

func (authStorage *AuthStorage) RemoveCurrentUser(ctx context.Context, email string) error {
	_, err := authStorage.pool.Exec(ctx, `
		delete from users where email = $1;
	`, email)
	if err != nil {
		return fmt.Errorf("%w (postgres.RemoveCurrentUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return nil
}

func (authStorage *AuthStorage) UpdateUserName(ctx context.Context, email string, newName string) error {
	_, err := authStorage.pool.Exec(ctx, `
		update users set name = $1 where email = $2;
	`, newName, email)
	if err != nil {
		return fmt.Errorf("%w (postgres.UpdateUserName): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return nil
}

func (authStorage *AuthStorage) GetAllUsers(ctx context.Context, dispatcherEmail string) ([]domain.UserSession, error) {
	tx, err := authStorage.pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrFailedToBeginTx, err)
	}
	defer func() {
		err = tx.Rollback(context.Background())
		if err != nil {
			fmt.Printf("%v (postgres.GetAllUsers): %v", customErrors.ErrFailedToRollbackTx, err)
		}
	}()

	var (
		permissionsLevel uint32
		plist            []string
	)
	err = tx.QueryRow(ctx, `
		select u.permissions_level, p.plist
		from users u, permission p
		where u.permissions_level = p.level and u.email = $1;
	`, dispatcherEmail).Scan(
		&permissionsLevel, &plist)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrDoesNotExist, err)
		}

		return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if !slices.Contains(plist, "user:getall") {
		return nil, fmt.Errorf("%w (postgres.GetAllUsers)", customErrors.ErrPermissionsDenied)
	}

	users := make([]domain.UserSession, 0)

	rows, err := tx.Query(ctx, `
		select uuid, name, email, permissions_level, registered_at
		from users
		where permissions_level < $1;
	`, permissionsLevel)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return users, nil
		}

		return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	for rows.Next() {
		var user domain.UserSession

		err = rows.Scan(&user.Uuid, &user.Name, &user.Email, &user.PermissionsLevel, &user.RegisteredAt)
		if err != nil {
			return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrFailedToExecuteQuery, err)
		}

		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return nil, fmt.Errorf("%w (postgres.GetAllUsers): %w", customErrors.ErrFailedToCommitTx, err)
	}

	return users, nil
}

func (authStorage *AuthStorage) RemoveUser(ctx context.Context, dispatcherEmail string, targetEmail string) error {
	tx, err := authStorage.pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrFailedToBeginTx, err)
	}
	defer func() {
		err = tx.Rollback(context.Background())
		if err != nil {
			fmt.Printf("%v (postgres.RemoveUser): %v", customErrors.ErrFailedToRollbackTx, err)
		}
	}()

	var (
		dispatcherPermissions uint32
		plist                 []string
	)
	err = tx.QueryRow(ctx, `
		select u.permissions_level, p.plist
		from users u, permission p
		where u.permissions_level = p.level and u.email = $1;
	`, dispatcherEmail).Scan(
		&dispatcherPermissions,
		&plist)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrDoesNotExist, err)
		}

		return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if !slices.Contains(plist, "user:remove") {
		return fmt.Errorf("%w (postgres.RemoveUser)", customErrors.ErrPermissionsDenied)
	}

	var targetPermissions uint32
	err = tx.QueryRow(ctx, `
		select permissions_level
		from users
		where email = $1;
	`, targetEmail).Scan(
		&targetPermissions)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrDoesNotExist, err)
		}

		return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if targetPermissions >= dispatcherPermissions {
		return fmt.Errorf("%w (postgres.RemoveUser)", customErrors.ErrPermissionsDenied)
	}

	_, err = tx.Exec(ctx, `
		delete from users where email = $1;
	`, targetEmail)
	if err != nil {
		return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return fmt.Errorf("%w (postgres.RemoveUser): %w", customErrors.ErrFailedToCommitTx, err)
	}

	return nil
}

func (authStorage *AuthStorage) BanUser(ctx context.Context, dispatcherEmail string, targetEmail string) error {
	tx, err := authStorage.pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrFailedToBeginTx, err)
	}
	defer func() {
		err = tx.Rollback(context.Background())
		if err != nil {
			fmt.Printf("%v (postgres.BanUser): %v", customErrors.ErrFailedToRollbackTx, err)
		}
	}()

	var (
		dispatcherPermissions uint32
		plist                 []string
	)
	err = tx.QueryRow(ctx, `
		select u.permissions_level, p.plist
		from users u, permission p
		where u.permissions_level = p.level and u.email = $1;
	`, dispatcherEmail).Scan(
		&dispatcherPermissions,
		&plist)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrDoesNotExist, err)
		}

		return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if !slices.Contains(plist, "user:ban") {
		return fmt.Errorf("%w (postgres.BanUser)", customErrors.ErrPermissionsDenied)
	}

	var targetPermissions uint32
	err = tx.QueryRow(ctx, `
		select permissions_level
		from users
		where email = $1;
	`, targetEmail).Scan(
		&targetPermissions)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrDoesNotExist, err)
		}

		return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if targetPermissions >= dispatcherPermissions {
		return fmt.Errorf("%w (postgres.BanUser)", customErrors.ErrPermissionsDenied)
	}

	_, err = tx.Exec(ctx, `
		update users set permissions_level = 0 where email = $1;
	`, targetEmail)
	if err != nil {
		return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return fmt.Errorf("%w (postgres.BanUser): %w", customErrors.ErrFailedToCommitTx, err)
	}

	return nil
}

func (authStorage *AuthStorage) UnBanUser(ctx context.Context, dispatcherEmail string, targetEmail string) error {
	tx, err := authStorage.pool.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrFailedToBeginTx, err)
	}
	defer func() {
		err = tx.Rollback(context.Background())
		if err != nil {
			fmt.Printf("%v (postgres.UnBanUser): %v", customErrors.ErrFailedToRollbackTx, err)
		}
	}()

	var (
		dispatcherPermissions uint32
		plist                 []string
	)
	err = tx.QueryRow(ctx, `
		select u.permissions_level, p.plist
		from users u, permission p
		where u.permissions_level = p.level and u.email = $1;
	`, dispatcherEmail).Scan(
		&dispatcherPermissions,
		&plist)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrDoesNotExist, err)
		}

		return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if !slices.Contains(plist, "user:unban") {
		return fmt.Errorf("%w (postgres.UnBanUser)", customErrors.ErrPermissionsDenied)
	}

	var targetPermissions uint32
	err = tx.QueryRow(ctx, `
		select permissions_level
		from users
		where email = $1;
	`, targetEmail).Scan(
		&targetPermissions)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrDoesNotExist, err)
		}

		return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	if targetPermissions >= dispatcherPermissions {
		return fmt.Errorf("%w (postgres.UnBanUser)", customErrors.ErrPermissionsDenied)
	}

	_, err = tx.Exec(ctx, `
		update users set permissions_level = 1 where email = $1;
	`, targetEmail)
	if err != nil {
		return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	err = tx.Commit(context.Background())
	if err != nil {
		return fmt.Errorf("%w (postgres.UnBanUser): %w", customErrors.ErrFailedToCommitTx, err)
	}

	return nil
}

func (authStorage *AuthStorage) FillRoles(ctx context.Context, roles []domain.Role) error {
	rolesToUpload := make([][]interface{}, len(roles))

	for i, role := range roles {
		rolesToUpload[i] = []interface{}{
			role.Level,
			role.Name,
			role.Permissions,
		}
	}

	_, err := authStorage.pool.CopyFrom(ctx, pgx.Identifier{"permission"}, []string{"level", "name", "plist"},
		pgx.CopyFromRows(rolesToUpload))
	if err != nil {
		return fmt.Errorf("%w (postgres.FillRoles): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return nil
}

func (authStorage *AuthStorage) FillUsers(ctx context.Context, users []domain.UserCredantialsFull) error {
	usersToUpload := make([][]interface{}, len(users))

	for i, user := range users {
		usersToUpload[i] = []interface{}{
			user.Name,
			user.Email,
			user.Password,
			user.PermissionsLevel,
		}
	}

	_, err := authStorage.pool.CopyFrom(
		ctx,
		pgx.Identifier{"users"},
		[]string{"name", "email", "password", "permissions_level"},
		pgx.CopyFromRows(usersToUpload))
	if err != nil {
		return fmt.Errorf("%w (postgres.FillUsers): %w", customErrors.ErrFailedToExecuteQuery, err)
	}

	return nil
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
