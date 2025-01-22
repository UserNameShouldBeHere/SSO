package api

import (
	"context"

	"google.golang.org/grpc/status"

	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
	sso "github.com/UserNameShouldBeHere/SSO/internal/proto"
)

type AuthService interface {
	CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) (string, error)
	LoginUser(ctx context.Context, userCreds domain.UserCredantialsLog) (string, error)
	Check(ctx context.Context, token string) bool
}

type SSOServer struct {
	authService AuthService
	sso.UnimplementedSSOServer
}

func NewSSOServer(authService AuthService) (*SSOServer, error) {
	return &SSOServer{
		authService: authService,
	}, nil
}

func (server *SSOServer) SignUp(ctx context.Context, req *sso.SignUpRequest) (resp *sso.SignUpResponse, err error) {
	userCreds := domain.UserCredantialsReg{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
	}

	if err := userCreds.Validate(); err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	token, err := server.authService.CreateUser(ctx, userCreds)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.SignUpResponse{
		Token: token,
	}, nil
}

func (server *SSOServer) SignIn(ctx context.Context, req *sso.SignInRequest) (resp *sso.SignInResponse, err error) {
	userCreds := domain.UserCredantialsLog{
		Email:    req.Email,
		Password: req.Password,
	}

	if err := userCreds.Validate(); err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	token, err := server.authService.LoginUser(ctx, userCreds)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.SignInResponse{
		Token: token,
	}, nil
}

func (server *SSOServer) Check(ctx context.Context, req *sso.CheckRequest) (resp *sso.CheckResponse, err error) {
	if len(req.Token) == 0 {
		return nil, status.Error(customErrors.GetGrpcStatus(customErrors.ErrDataNotValid), err.Error())
	}

	stat := server.authService.Check(ctx, req.Token)

	return &sso.CheckResponse{
		Stat: stat,
	}, nil
}
