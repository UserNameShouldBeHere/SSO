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

	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type AuthStorage interface {
	CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) error
	GetPassword(ctx context.Context, email string) (string, error)
	GetUser(ctx context.Context, email string) (domain.User, error)
	RemoveUser(ctx context.Context, email string) error
	GetAllUsers(ctx context.Context, email string) ([]domain.UserSession, error)
}

type SessionStorage interface {
	CreateSession(ctx context.Context, email string) (string, error)
	Check(ctx context.Context, token string) (bool, error)
	LogoutCurrent(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, token string) error
	LogoutSession(ctx context.Context, token string, tokenForLogout string) error
	GetUserEmail(ctx context.Context, token string) (string, error)
	GetUserSessions(ctx context.Context, email string) ([]string, error)
	FlushExpiredSessions(ctx context.Context) error
}

type AuthService struct {
	authStorage    AuthStorage
	sessionStorage SessionStorage
	logger         *zap.SugaredLogger
	saltLength     int
}

func NewAuthService(
	authStorage AuthStorage, sessionStorage SessionStorage, logger *zap.SugaredLogger) (*AuthService, error) {

	go func() {
		for {
			err := sessionStorage.FlushExpiredSessions(context.Background())
			if err != nil {
				logger.Errorf("failed to flush expired sessions (service.NewAuthService): %w", err)
			}

			time.Sleep(time.Minute * 10)
		}
	}()

	return &AuthService{
		authStorage:    authStorage,
		sessionStorage: sessionStorage,
		logger:         logger,
		saltLength:     10,
	}, nil
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
	expectedPassword, err := authService.authStorage.GetPassword(ctx, userCreds.Email)
	if err != nil {
		if errors.Is(err, customErrors.ErrDoesNotExist) {
			authService.logger.Errorf("user doesn't exist (service.LoginUser)")
			return "", fmt.Errorf("%w (service.LoginUser)", customErrors.ErrIncorrectEmailOrPassword)
		}

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
	err := authService.sessionStorage.LogoutCurrent(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.LogoutCurrent): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) LogoutAll(ctx context.Context, token string) error {
	err := authService.sessionStorage.LogoutAll(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.LogoutAll): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) LogoutSession(ctx context.Context, token string, tokenForLogout string) error {
	err := authService.sessionStorage.LogoutSession(ctx, token, tokenForLogout)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.LogoutSession): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) GetUser(ctx context.Context, token string) (domain.User, error) {
	email, err := authService.sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get user email (service.GetUser): %w", err)
		return domain.User{}, err
	}

	user, err := authService.authStorage.GetUser(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to get user data (service.GetUser): %w", err)
		return domain.User{}, err
	}

	return user, nil
}

func (authService *AuthService) RemoveUser(ctx context.Context, token string) error {
	email, err := authService.sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get user email (service.RemoveUser): %w", err)
		return err
	}

	err = authService.sessionStorage.LogoutAll(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.RemoveUser): %w", err)
		return err
	}

	err = authService.authStorage.RemoveUser(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to remove user (service.RemoveUser): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) GetAllSessions(ctx context.Context, token string) ([]string, error) {
	email, err := authService.sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get user email (service.GetAllSessions): %w", err)
		return nil, err
	}

	tokens, err := authService.sessionStorage.GetUserSessions(ctx, email)
	if err != nil {
		authService.logger.Errorf("failed to get user sessions (service.GetAllSessions): %w", err)
		return nil, err
	}

	return tokens, nil
}

func (authService *AuthService) GetUsersSessions(ctx context.Context, token string) ([]domain.UserSession, error) {
	email, err := authService.sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to get user email (service.GetUsersSessions): %w", err)
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
