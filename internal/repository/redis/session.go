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
	jwtKey         []byte
}

func NewSessionStorage(rdb *redis.Client, tokenExpiration int) (*SessionStorage, error) {
	jwtKey := make([]byte, 16)
	_, err := rand.Read(jwtKey)
	if err != nil {
		return nil, fmt.Errorf("%w (redis.NewSessionStorage): %w", customErrors.ErrFailedToGenJWTKey, err)
	}

	return &SessionStorage{
		rdb:            rdb,
		expirationTime: tokenExpiration,
		jwtKey:         jwtKey,
	}, nil
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
	claims, err := sessionStorage.getTokenClaims(token)
	if err != nil {
		return false, fmt.Errorf("%w (redis.Check): %w", customErrors.ErrFailedToSignToken, err)
	}

	email, ok := (*claims)["email"]

	if !ok {
		return false, fmt.Errorf("%w (redis.Check)", customErrors.ErrFailedToSignToken)
	}

	err = sessionStorage.rdb.SIsMember(ctx, email.(string), token).Err()
	if err != nil {
		return false, fmt.Errorf("%w (redis.Check): %w", customErrors.ErrUnauthenticated, err)
	}

	return true, nil
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
