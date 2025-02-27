package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"

	ssoconfig "github.com/UserNameShouldBeHere/SSO/internal/config"
	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type AuthStorage interface {
	CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) error
	GetPassword(ctx context.Context, email string) (string, error)
	GetPermissionsLevel(ctx context.Context, email string) (uint32, error)
	GetUser(ctx context.Context, email string) (domain.User, error)
	RemoveCurrentUser(ctx context.Context, email string) error
	UpdateUserName(ctx context.Context, email string, newName string) error
	GetAllUsers(ctx context.Context, dispatcherEmail string) ([]domain.UserSession, error)
	RemoveUser(ctx context.Context, dispatcherEmail string, targetEmail string) error
	BanUser(ctx context.Context, dispatcherEmail string, targetEmail string) error
	UnBanUser(ctx context.Context, dispatcherEmail string, targetEmail string) error
	FillRoles(ctx context.Context, roles []domain.Role) error
	FillUsers(ctx context.Context, users []domain.UserCredantialsFull) error
}

type SessionStorage interface {
	CreateSession(ctx context.Context, email string) (string, error)
	Check(ctx context.Context, token string) (bool, error)
	CheckWithEmail(ctx context.Context, email string, token string) (bool, error)
	LogoutCurrent(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, token string) error
	LogoutAllByEmail(ctx context.Context, email string) error
	LogoutSession(ctx context.Context, token string, tokenForLogout string) error
	GetUserEmail(ctx context.Context, token string) (string, error)
	GetUserSessions(ctx context.Context, email string) ([]string, error)
}

type AuthService struct {
	authStorage    AuthStorage
	sessionStorage SessionStorage
	logger         *zap.SugaredLogger
	saltLength     int
}

func NewAuthService(
	authStorage AuthStorage,
	sessionStorage SessionStorage,
	logger *zap.SugaredLogger,
	myConfig *ssoconfig.Config) (*AuthService, error) {

	authService := AuthService{
		authStorage:    authStorage,
		sessionStorage: sessionStorage,
		logger:         logger,
		saltLength:     myConfig.Server.SaltLength,
	}

	go func() {
		roles := make([]domain.Role, len(myConfig.Roles))
		users := make([]domain.UserCredantialsFull, len(myConfig.Users))

		for i, role := range myConfig.Roles {
			roles[i] = domain.Role{
				Level:       role.Id,
				Name:        role.Name,
				Permissions: role.Permissions,
			}
		}

		for i, user := range myConfig.Users {
			users[i] = domain.UserCredantialsFull{
				Email:            user.Email,
				Name:             user.Name,
				Password:         user.Password,
				PermissionsLevel: user.RoleId,
			}
		}

		// used to wait until database container starts
		time.Sleep(time.Second * 10)

		err := authService.fillRoles(context.Background(), roles)
		if err != nil {
			authService.logger.Errorf("%w (service.NewAuthService): %w", customErrors.ErrInternal, err)
		}

		err = authService.fillUsers(context.Background(), users)
		if err != nil {
			authService.logger.Errorf("%w (service.NewAuthService): %w", customErrors.ErrInternal, err)
		}
	}()

	return &authService, nil
}

func (authService *AuthService) CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) (string, error) {
	salt, err := genRandomSalt(authService.saltLength)
	if err != nil {
		authService.logger.Errorf("failed to generate salt (service.CreateUser): %w", err)
		return "", fmt.Errorf("%w (service.CreateUser): %w", customErrors.ErrInternal, err)
	}

	hash, err := hashPassword(userCreds.Password, salt)
	if err != nil {
		authService.logger.Errorf("failed to hash password (service.CreateUser): %w", err)
		return "", fmt.Errorf("%w (service.CreateUser): %w", customErrors.ErrInternal, err)
	}

	hashedPassword := append(salt, hash...)

	userCreds.Password = base64.RawStdEncoding.EncodeToString(hashedPassword)

	err = authService.authStorage.CreateUser(ctx, userCreds)
	if err != nil {
		authService.logger.Errorf("failed to create user (service.CreateUser): %w", err)
		return "", fmt.Errorf("(service.CreateUser): %w", err)
	}

	token, err := authService.sessionStorage.CreateSession(ctx, userCreds.Email)
	if err != nil {
		authService.logger.Errorf("failed to create session (service.CreateUser): %w", err)
		return "", fmt.Errorf("(service.CreateUser): %w", err)
	}

	return token, nil
}

func (authService *AuthService) LoginUser(ctx context.Context, userCreds domain.UserCredantialsLog) (string, error) {
	permissionsLevel, err := authService.authStorage.GetPermissionsLevel(ctx, userCreds.Email)
	if err != nil {
		if errors.Is(err, customErrors.ErrDoesNotExist) {
			authService.logger.Errorf("user doesn't exist (service.LoginUser)")
			return "", fmt.Errorf("%w (service.LoginUser)", customErrors.ErrIncorrectEmailOrPassword)
		}

		authService.logger.Errorf("failed to get password (service.LoginUser): %w", err)
		return "", fmt.Errorf("(service.LoginUser): %w", err)
	}

	if permissionsLevel == 0 {
		authService.logger.Errorf("user banned (service.LoginUser)")
		return "", fmt.Errorf("%w (service.LoginUser)", customErrors.ErrPermissionsDenied)
	}

	expectedPassword, err := authService.authStorage.GetPassword(ctx, userCreds.Email)
	if err != nil {
		authService.logger.Errorf("failed to get password (service.LoginUser): %w", err)
		return "", fmt.Errorf("(service.LoginUser): %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(expectedPassword)
	if err != nil {
		authService.logger.Errorf("failed to decode password (service.LoginUser): %w", err)
		return "", fmt.Errorf("%w (service.LoginUser): %w", customErrors.ErrInternal, err)
	}

	salt := expectedHash[0:authService.saltLength]
	givenHash, err := hashPassword(userCreds.Password, salt)
	if err != nil {
		authService.logger.Errorf("failed to hash password (service.LoginUser): %w", err)
		return "", fmt.Errorf("%w (service.LoginUser): %w", customErrors.ErrInternal, err)
	}

	givenPassword := append(salt, givenHash...)

	if expectedPassword != base64.RawStdEncoding.EncodeToString(givenPassword) {
		authService.logger.Errorf("passwords do not match (service.LoginUser)")
		return "", fmt.Errorf("%w (service.LoginUser)", customErrors.ErrIncorrectEmailOrPassword)
	}

	token, err := authService.sessionStorage.CreateSession(ctx, userCreds.Email)
	if err != nil {
		authService.logger.Errorf("failed to create session (service.LoginUser): %w", err)
		return "", fmt.Errorf("(service.LoginUser): %w", err)
	}

	return token, nil
}

func (authService *AuthService) Check(ctx context.Context, token string) bool {
	stat, err := authService.sessionStorage.Check(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to check session (service.Check): %w", err)
		return false
	}

	return stat
}

func (authService *AuthService) LogoutCurrent(ctx context.Context, token string) error {
	stat, err := authService.sessionStorage.Check(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to check session (service.LogoutCurrent): %w", err)
		return err
	}

	if !stat {
		authService.logger.Errorf("unauthenticated (service.LogoutCurrent)")
		return fmt.Errorf("%w (service.LogoutCurrent)", customErrors.ErrUnauthenticated)
	}

	err = authService.sessionStorage.LogoutCurrent(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.LogoutCurrent): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) LogoutAll(ctx context.Context, token string) error {
	stat, err := authService.sessionStorage.Check(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to check session (service.LogoutAll): %w", err)
		return err
	}

	if !stat {
		authService.logger.Errorf("unauthenticated (service.LogoutAll)")
		return fmt.Errorf("%w (service.LogoutAll)", customErrors.ErrUnauthenticated)
	}

	err = authService.sessionStorage.LogoutAll(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.LogoutAll): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) LogoutSession(ctx context.Context, token string, tokenForLogout string) error {
	stat, err := authService.sessionStorage.Check(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to check session (service.LogoutSession): %w", err)
		return err
	}

	if !stat {
		authService.logger.Errorf("unauthenticated (service.LogoutSession)")
		return fmt.Errorf("%w (service.LogoutSession)", customErrors.ErrUnauthenticated)
	}

	err = authService.sessionStorage.LogoutSession(ctx, token, tokenForLogout)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.LogoutSession): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) GetUser(ctx context.Context, token string) (domain.User, error) {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.GetUser): %w", err)
		return domain.User{}, err
	}

	user, err := authService.authStorage.GetUser(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to get user data (service.GetUser): %w", err)
		return domain.User{}, err
	}

	return user, nil
}

func (authService *AuthService) RemoveCurrentUser(ctx context.Context, token string) error {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.RemoveCurrentUser): %w", err)
		return err
	}

	err = authService.sessionStorage.LogoutAll(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.RemoveCurrentUser): %w", err)
		return err
	}

	err = authService.authStorage.RemoveCurrentUser(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to remove user (service.RemoveCurrentUser): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) GetAllSessions(ctx context.Context, token string) ([]string, error) {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.GetAllSessions): %w", err)
		return nil, err
	}

	tokens, err := authService.sessionStorage.GetUserSessions(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to get user sessions (service.GetAllSessions): %w", err)
		return nil, err
	}

	return tokens, nil
}

func (authService *AuthService) UpdateUserName(ctx context.Context, token string, newName string) error {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.UpdateUserName): %w", err)
		return err
	}

	err = authService.authStorage.UpdateUserName(ctx, email, newName)
	if err != nil {
		authService.logger.Errorf("failed to get all users (service.UpdateUserName): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) GetUsersSessions(ctx context.Context, token string) ([]domain.UserSession, error) {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.GetUsersSessions): %w", err)
		return nil, err
	}

	users, err := authService.authStorage.GetAllUsers(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to get all users (service.GetUsersSessions): %w", err)
		return nil, err
	}

	for i, user := range users {
		tokens, err := authService.sessionStorage.GetUserSessions(ctx, user.Email)
		if err != nil {
			authService.logger.Errorf("failed to get user sessions (service.GetUsersSessions): %w", err)
			return nil, err
		}

		users[i].Tokens = tokens
	}

	return users, nil
}

func (authService *AuthService) RemoveUser(ctx context.Context, token string, targetEmail string) error {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.RemoveUser): %w", err)
		return err
	}

	err = authService.authStorage.RemoveUser(ctx, email, targetEmail)
	if err != nil {
		authService.logger.Errorf("failed to remove user (service.RemoveUser): %w", err)
		return err
	}

	err = authService.sessionStorage.LogoutAllByEmail(ctx, targetEmail)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.RemoveUser): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) BanUser(ctx context.Context, token string, targetEmail string) error {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.BanUser): %w", err)
		return err
	}

	err = authService.authStorage.BanUser(ctx, email, targetEmail)
	if err != nil {
		authService.logger.Errorf("failed to ban user (service.BanUser): %w", err)
		return err
	}

	err = authService.sessionStorage.LogoutAllByEmail(ctx, targetEmail)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.BanUser): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) UnBanUser(ctx context.Context, token string, targetEmail string) error {
	email, err := authService.getEmailAndCHeck(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get check session (service.UnBanUser): %w", err)
		return err
	}

	err = authService.authStorage.UnBanUser(ctx, email, targetEmail)
	if err != nil {
		authService.logger.Errorf("failed to get unban user (service.UnBanUser): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) getEmailAndCHeck(ctx context.Context, token string) (string, error) {
	email, err := authService.sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		return "", fmt.Errorf("failed to get user email (service.getEmailAndCHeck): %w", err)
	}

	stat, err := authService.sessionStorage.CheckWithEmail(ctx, email, token)
	if err != nil {
		return "", fmt.Errorf("failed to check session (service.getEmailAndCHeck): %w", err)
	}

	if !stat {
		return "", fmt.Errorf("%w (service.getEmailAndCHeck)", customErrors.ErrUnauthenticated)
	}

	return email, nil
}

func (authService *AuthService) fillRoles(ctx context.Context, roles []domain.Role) error {
	err := authService.authStorage.FillRoles(ctx, roles)
	if err != nil {
		authService.logger.Errorf("failed to fill roles (service.FillRoles): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) fillUsers(ctx context.Context, users []domain.UserCredantialsFull) error {
	for i := range users {
		salt, err := genRandomSalt(authService.saltLength)
		if err != nil {
			authService.logger.Errorf("failed to generate salt (service.FillUsers): %w", err)
			return fmt.Errorf("%w (service.FillUsers): %w", customErrors.ErrInternal, err)
		}

		hash, err := hashPassword(users[i].Password, salt)
		if err != nil {
			authService.logger.Errorf("failed to hash password (service.FillUsers): %w", err)
			return fmt.Errorf("%w (service.FillUsers): %w", customErrors.ErrInternal, err)
		}

		hashedPassword := append(salt, hash...)

		users[i].Password = base64.RawStdEncoding.EncodeToString(hashedPassword)
	}

	err := authService.authStorage.FillUsers(ctx, users)
	if err != nil {
		authService.logger.Errorf("failed to fill users (service.FillUsers): %w", err)
		return err
	}

	return nil
}

func hashPassword(password string, salt []byte) ([]byte, error) {
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return hash, nil
}

func genRandomSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}
