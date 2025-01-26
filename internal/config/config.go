package config

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type Config struct {
	Roles []struct {
		Name        string   `yaml:"name"`
		Id          uint32   `yaml:"id"`
		Permissions []string `yaml:"permissions,omitempty"`
	} `yaml:"roles"`
	Users []struct {
		Email    string `yaml:"email"`
		Name     string `yaml:"name"`
		Password string `yaml:"password"`
		RoleId   uint32 `yaml:"role-id"`
	} `yaml:"users,omitempty"`
	Server struct {
		SessionExpiration int `yaml:"session-expiration"`
		FlushInterval     int `yaml:"flush-interval"`
	} `yaml:"server"`
}

type AuthService interface {
	FillRoles(ctx context.Context, roles []domain.Role) error
	FillUsers(ctx context.Context, users []domain.UserCredantialsFull) error
}

func NewConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	if err = config.parse(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (config *Config) parse() error {
	rolesIds := make(map[uint32]struct{})
	rolesNames := make(map[string]struct{})
	users := make(map[string]struct{})

	for _, role := range config.Roles {
		_, ok := rolesIds[role.Id]
		if ok {
			return fmt.Errorf("%w (config.parse): role with id '%d' already exists", customErrors.ErrAlreadyExists, role.Id)
		}

		_, ok = rolesNames[role.Name]
		if ok {
			return fmt.Errorf("%w (config.parse): role with name '%s' already exists", customErrors.ErrAlreadyExists, role.Name)
		}

		rolesIds[role.Id] = struct{}{}
		rolesNames[role.Name] = struct{}{}
	}

	for _, user := range config.Users {
		_, ok := users[user.Email]
		if ok {
			return fmt.Errorf("%w (config.parse): user with email '%s' already exists", customErrors.ErrAlreadyExists, user.Email)
		}

		users[user.Email] = struct{}{}

		userCreds := domain.UserCredantialsFull{
			Email:            user.Email,
			Name:             user.Name,
			Password:         user.Password,
			PermissionsLevel: user.RoleId,
		}

		if err := userCreds.Validate(); err != nil {
			return fmt.Errorf("%w (config.parse): %w", customErrors.ErrDataNotValid, err)
		}
	}

	return nil
}

func (config *Config) FillDB(ctx context.Context, authService AuthService) error {
	roles := make([]domain.Role, len(config.Roles))
	users := make([]domain.UserCredantialsFull, len(config.Users))

	for i, role := range config.Roles {
		roles[i] = domain.Role{
			Level:       role.Id,
			Name:        role.Name,
			Permissions: role.Permissions,
		}
	}

	for i, user := range config.Users {
		users[i] = domain.UserCredantialsFull{
			Email:            user.Email,
			Name:             user.Name,
			Password:         user.Password,
			PermissionsLevel: user.RoleId,
		}
	}

	err := authService.FillRoles(ctx, roles)
	if err != nil {
		return fmt.Errorf("%w (config.FillDB): %w", customErrors.ErrInternal, err)
	}

	err = authService.FillUsers(ctx, users)
	if err != nil {
		return fmt.Errorf("%w (config.FillDB): %w", customErrors.ErrInternal, err)
	}

	return nil
}
