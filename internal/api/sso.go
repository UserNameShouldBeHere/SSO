package api

import (
	"context"
	"time"

	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/UserNameShouldBeHere/SSO/internal/domain"
	customErrors "github.com/UserNameShouldBeHere/SSO/internal/errors"
	sso "github.com/UserNameShouldBeHere/SSO/internal/proto"
)

type AuthService interface {
	CreateUser(ctx context.Context, userCreds domain.UserCredantialsReg) (string, error)
	LoginUser(ctx context.Context, userCreds domain.UserCredantialsLog) (string, error)
	Check(ctx context.Context, token string) bool
	LogoutCurrent(ctx context.Context, token string) error
	LogoutAll(ctx context.Context, token string) error
	LogoutSession(ctx context.Context, token string, tokenForLogout string) error
	GetUser(ctx context.Context, token string) (domain.User, error)
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
		return nil, status.Error(customErrors.GetGrpcStatus(customErrors.ErrDataNotValid), "incorrect token")
	}

	stat := server.authService.Check(ctx, req.Token)

	return &sso.CheckResponse{
		Stat: stat,
	}, nil
}

func (server *SSOServer) LogoutCurrent(
	ctx context.Context, req *sso.LogoutRequest) (resp *sso.LogoutResponse, err error) {

	err = server.authService.LogoutCurrent(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.LogoutResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) LogoutAll(ctx context.Context, req *sso.LogoutRequest) (resp *sso.LogoutResponse, err error) {
	err = server.authService.LogoutAll(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.LogoutResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) LogoutSession(
	ctx context.Context, req *sso.LogoutSessionRequest) (resp *sso.LogoutResponse, err error) {

	err = server.authService.LogoutSession(ctx, req.Token, req.TokenForLogout)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.LogoutResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) GetUser(ctx context.Context, req *sso.GetUserRequest) (resp *sso.GetUserResponse, err error) {
	user, err := server.authService.GetUser(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.GetUserResponse{
		User: &sso.User{
			Uuid:             user.Uuid,
			Name:             user.Name,
			Email:            user.Email,
			PermissionsLevel: user.PermissionsLevel,
			RegisteredAt:     convertTimeToProto(user.RegisteredAt),
		},
	}, nil
}

func convertTimeToProto(time time.Time) *timestamppb.Timestamp {
	return &timestamppb.Timestamp{
		Seconds: time.Unix(),
		Nanos:   int32(time.Nanosecond()),
	}
}
