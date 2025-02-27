package domain

import (
	"fmt"

	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
)

type UserCredantialsReg struct {
	Name     string
	Email    string
	Password string
}

type UserCredantialsLog struct {
	Email    string
	Password string
}

type UserCredantialsFull struct {
	Name             string
	Email            string
	Password         string
	PermissionsLevel uint32
}

func (userCredantialsReg *UserCredantialsReg) Validate() error {
	if len(userCredantialsReg.Name) < 3 ||
		len(userCredantialsReg.Name) >= 64 {
		return fmt.Errorf("%w (Validate): incorrect name length", customErrors.ErrDataNotValid)
	}

	if len(userCredantialsReg.Email) < 3 ||
		len(userCredantialsReg.Email) >= 320 {
		return fmt.Errorf("%w (Validate): incorrect email length", customErrors.ErrDataNotValid)
	}

	if len(userCredantialsReg.Password) == 0 {
		return fmt.Errorf("%w (Validate): incorrect password length", customErrors.ErrDataNotValid)
	}

	return nil
}

func (userCredantialsFull *UserCredantialsFull) Validate() error {
	if len(userCredantialsFull.Name) < 3 ||
		len(userCredantialsFull.Name) >= 64 {
		return fmt.Errorf("%w (Validate): incorrect name length", customErrors.ErrDataNotValid)
	}

	if len(userCredantialsFull.Email) < 3 ||
		len(userCredantialsFull.Email) >= 320 {
		return fmt.Errorf("%w (Validate): incorrect email length", customErrors.ErrDataNotValid)
	}

	if len(userCredantialsFull.Password) == 0 {
		return fmt.Errorf("%w (Validate): incorrect password length", customErrors.ErrDataNotValid)
	}

	return nil
}

func (userCredantialsLog *UserCredantialsLog) Validate() error {
	if len(userCredantialsLog.Email) < 3 ||
		len(userCredantialsLog.Email) >= 320 {
		return fmt.Errorf("%w (Validate): incorrect email length", customErrors.ErrDataNotValid)
	}

	if len(userCredantialsLog.Password) == 0 {
		return fmt.Errorf("%w (Validate): incorrect password length", customErrors.ErrDataNotValid)
	}

	return nil
}
