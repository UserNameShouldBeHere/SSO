package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"

	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type AuthStorage interface {
	CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) error
	GetPassword(ctx context.Context, email string) (string, error)
}

type SessionStorage interface {
	CreateSession(ctx context.Context, email string) (string, error)
	Check(ctx context.Context, token string) (bool, error)
	LogoutCurrent(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, token string) error
	LogoutSession(ctx context.Context, token string, tokenForLogout string) error
}

type AuthService struct {
	authStorage    AuthStorage
	sessionStorage SessionStorage
	logger         *zap.SugaredLogger
	saltLength     int
}

func NewAuthService(
	authStorage AuthStorage, sessionStorage SessionStorage, logger *zap.SugaredLogger) (*AuthService, error) {

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
		authService.logger.Errorf("failed to logout session (service.Logout): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) LogoutAll(ctx context.Context, token string) error {
	err := authService.sessionStorage.LogoutAll(ctx, token)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.Logout): %w", err)
		return err
	}

	return nil
}

func (authService *AuthService) LogoutSession(ctx context.Context, token string, tokenForLogout string) error {
	err := authService.sessionStorage.LogoutSession(ctx, token, tokenForLogout)
	if err != nil {
		authService.logger.Errorf("failed to logout session (service.Logout): %w", err)
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
