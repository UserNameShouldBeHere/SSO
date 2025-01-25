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
	RemoveCurrentUser(ctx context.Context, token string) error
	GetAllSessions(ctx context.Context, token string) ([]string, error)
	UpdateUserName(ctx context.Context, token string, newName string) error
	GetUsersSessions(ctx context.Context, token string) ([]domain.UserSession, error)
	RemoveUser(ctx context.Context, token string, targetEmail string) error
	BanUser(ctx context.Context, token string, targetEmail string) error
	UnBanUser(ctx context.Context, token string, targetEmail string) error
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

func (server *SSOServer) Check(ctx context.Context, req *sso.TokenRequest) (resp *sso.StatusResponse, err error) {
	if len(req.Token) == 0 {
		return nil, status.Error(customErrors.GetGrpcStatus(customErrors.ErrDataNotValid), "incorrect token")
	}

	stat := server.authService.Check(ctx, req.Token)

	return &sso.StatusResponse{
		Stat: stat,
	}, nil
}

func (server *SSOServer) LogoutCurrent(
	ctx context.Context, req *sso.TokenRequest) (resp *sso.StatusResponse, err error) {

	err = server.authService.LogoutCurrent(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) LogoutAll(ctx context.Context, req *sso.TokenRequest) (resp *sso.StatusResponse, err error) {
	err = server.authService.LogoutAll(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) LogoutSession(
	ctx context.Context, req *sso.LogoutSessionRequest) (resp *sso.StatusResponse, err error) {

	err = server.authService.LogoutSession(ctx, req.Token, req.TokenForLogout)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) GetUser(ctx context.Context, req *sso.TokenRequest) (resp *sso.GetUserResponse, err error) {
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

func (server *SSOServer) RemoveCurrentUser(
	ctx context.Context, req *sso.TokenRequest) (resp *sso.StatusResponse, err error) {

	err = server.authService.RemoveCurrentUser(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) GetAllSessions(
	ctx context.Context, req *sso.TokenRequest) (resp *sso.GetAllSessionsResponse, err error) {

	tokens, err := server.authService.GetAllSessions(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.GetAllSessionsResponse{
		Tokens: tokens,
	}, nil
}

func (server *SSOServer) UpdateUserName(
	ctx context.Context, req *sso.UpdateUserNameRequest) (resp *sso.StatusResponse, err error) {

	err = server.authService.UpdateUserName(ctx, req.Token, req.NewName)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) GetAllUsers(
	ctx context.Context, req *sso.TokenRequest) (resp *sso.GetAllUsersResponse, err error) {

	users, err := server.authService.GetUsersSessions(ctx, req.Token)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	userSessions := make([]*sso.UserSession, 0)

	for _, user := range users {
		userSessions = append(userSessions, &sso.UserSession{
			Uuid:             user.Uuid,
			Email:            user.Email,
			Name:             user.Name,
			PermissionsLevel: user.PermissionsLevel,
			RegisteredAt:     convertTimeToProto(user.RegisteredAt),
			Tokens:           user.Tokens,
		})
	}

	return &sso.GetAllUsersResponse{
		Users: userSessions,
	}, nil
}

func (server *SSOServer) RemoveUser(ctx context.Context, req *sso.TargetRequest) (reso *sso.StatusResponse, err error) {
	err = server.authService.RemoveUser(ctx, req.Token, req.TargetEmail)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) BanUser(ctx context.Context, req *sso.TargetRequest) (resp *sso.StatusResponse, err error) {
	err = server.authService.BanUser(ctx, req.Token, req.TargetEmail)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func (server *SSOServer) UnBanUser(ctx context.Context, req *sso.TargetRequest) (resp *sso.StatusResponse, err error) {
	err = server.authService.UnBanUser(ctx, req.Token, req.TargetEmail)
	if err != nil {
		return nil, status.Error(customErrors.GetGrpcStatus(err), err.Error())
	}

	return &sso.StatusResponse{
		Stat: true,
	}, nil
}

func convertTimeToProto(time time.Time) *timestamppb.Timestamp {
	return &timestamppb.Timestamp{
		Seconds: time.Unix(),
		Nanos:   int32(time.Nanosecond()),
	}
}
