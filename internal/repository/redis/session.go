package redis

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/redis/go-redis/v9"

	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type SessionStorage struct {
	rdb            *redis.Client
	expirationTime int // in seconds
	flushInterval  int // in seconds
	jwtKey         []byte
}

func NewSessionStorage(rdb *redis.Client, tokenExpiration int, flushInterval int) (*SessionStorage, error) {
	jwtKey := make([]byte, 16)
	_, err := rand.Read(jwtKey)
	if err != nil {
		return nil, fmt.Errorf("%w (redis.NewSessionStorage): %w", customErrors.ErrFailedToGenJWTKey, err)
	}

	sessionStorage := &SessionStorage{
		rdb:            rdb,
		expirationTime: tokenExpiration,
		flushInterval:  flushInterval,
		jwtKey:         jwtKey,
	}

	go func() {
		for {
			err := sessionStorage.FlushExpiredSessions(context.Background())
			if err != nil {
				fmt.Printf("failed to flush expired sessions (redis.NewSessionStorage): %v", err)
			}

			time.Sleep(time.Second * time.Duration(flushInterval))
		}
	}()

	return sessionStorage, nil
}

func (sessionStorage *SessionStorage) CreateSession(ctx context.Context, email string) (string, error) {
	token, err := sessionStorage.createToken(email)
	if err != nil {
		return "", fmt.Errorf("%w (redis.CreateSession): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	err = sessionStorage.rdb.SAdd(ctx, email, token).Err()
	if err != nil {
		return "", fmt.Errorf("%w (redis.CreateSession): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	return token, nil
}

func (sessionStorage *SessionStorage) Check(ctx context.Context, token string) (bool, error) {
	email, err := sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		return false, fmt.Errorf("%w (redis.Check): %w", customErrors.ErrInternal, err)
	}

	boolCmd := sessionStorage.rdb.SIsMember(ctx, email, token)
	if err = boolCmd.Err(); err != nil {
		return false, fmt.Errorf("%w (redis.Check): %w", customErrors.ErrUnauthenticated, err)
	}

	return boolCmd.Val(), nil
}

func (sessionStorage *SessionStorage) CheckWithEmail(ctx context.Context, email string, token string) (bool, error) {
	boolCmd := sessionStorage.rdb.SIsMember(ctx, email, token)
	if err := boolCmd.Err(); err != nil {
		return false, fmt.Errorf("%w (redis.CheckWithEmail): %w", customErrors.ErrUnauthenticated, err)
	}

	return boolCmd.Val(), nil
}

func (sessionStorage *SessionStorage) LogoutCurrent(ctx context.Context, token string) error {
	email, err := sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutCurrent): %w", customErrors.ErrInternal, err)
	}

	err = sessionStorage.rdb.SRem(ctx, email, token).Err()
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutCurrent): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	return nil
}

func (sessionStorage *SessionStorage) LogoutAll(ctx context.Context, token string) error {
	email, err := sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutAll): %w", customErrors.ErrInternal, err)
	}

	err = sessionStorage.rdb.Del(ctx, email).Err()
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutAll): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	return nil
}

func (sessionStorage *SessionStorage) LogoutAllByEmail(ctx context.Context, email string) error {
	err := sessionStorage.rdb.Del(ctx, email).Err()
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutAllByEmail): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	return nil
}

func (sessionStorage *SessionStorage) LogoutSession(ctx context.Context, token string, tokenForLogout string) error {
	email, err := sessionStorage.GetUserEmail(ctx, token)
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutSession): %w", customErrors.ErrInternal, err)
	}

	err = sessionStorage.rdb.SRem(ctx, email, tokenForLogout).Err()
	if err != nil {
		return fmt.Errorf("%w (redis.LogoutSession): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	return nil
}

func (sessionStorage *SessionStorage) GetUserEmail(ctx context.Context, token string) (string, error) {
	claims, err := sessionStorage.getTokenClaims(token)
	if err != nil {
		return "", fmt.Errorf("%w (redis.GetUserEmail): %w", customErrors.ErrFailedToSignToken, err)
	}

	email, ok := (*claims)["email"]

	if !ok {
		return "", fmt.Errorf("%w (redis.GetUserEmail)", customErrors.ErrFailedToSignToken)
	}

	return email.(string), nil
}

func (sessionStorage *SessionStorage) GetUserSessions(ctx context.Context, email string) ([]string, error) {
	stringsCmd := sessionStorage.rdb.SMembers(ctx, email)
	if err := stringsCmd.Err(); err != nil {
		return nil, fmt.Errorf("%w (redis.GetUserSessions): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	return stringsCmd.Val(), nil
}

type myCustomClaims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func (sessionStorage *SessionStorage) createToken(email string) (string, error) {
	claims := myCustomClaims{
		email,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * time.Duration(sessionStorage.expirationTime)).Unix(),
			Issuer:    "sso",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(sessionStorage.jwtKey)
	if err != nil {
		return "", fmt.Errorf("%w (redis.createToken): %w", customErrors.ErrFailedToCreateToken, err)
	}

	return signedToken, nil
}

func (sessionStorage *SessionStorage) getTokenClaims(token string) (*jwt.MapClaims, error) {
	parsedToken, err := jwt.Parse(token,
		func(token *jwt.Token) (interface{}, error) {
			return sessionStorage.jwtKey, nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, err
	}

	return &claims, nil
}

func (sessionStorage *SessionStorage) FlushExpiredSessions(ctx context.Context) error {
	stringsCmd := sessionStorage.rdb.Keys(ctx, "*")
	if err := stringsCmd.Err(); err != nil {
		return fmt.Errorf("%w (redis.flushExpiredUserSessions): %w", customErrors.ErrFailedToExecuteMethod, err)
	}

	for _, user := range stringsCmd.Val() {
		stringsCmd = sessionStorage.rdb.SMembers(ctx, user)
		if err := stringsCmd.Err(); err != nil {
			return fmt.Errorf("%w (redis.flushExpiredUserSessions): %w", customErrors.ErrFailedToExecuteMethod, err)
		}

		for _, token := range stringsCmd.Val() {
			if _, err := sessionStorage.getTokenClaims(token); err != nil {
				err = sessionStorage.rdb.SRem(ctx, user, token).Err()
				if err != nil {
					return fmt.Errorf("%w (redis.flushExpiredUserSessions): %w", customErrors.ErrFailedToExecuteMethod, err)
				}
			}
		}
	}

	return nil
}
