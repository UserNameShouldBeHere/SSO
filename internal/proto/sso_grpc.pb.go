// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.24.2
// source: proto/sso.proto

package sso

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	SSO_SignUp_FullMethodName        = "/sso.SSO/SignUp"
	SSO_SignIn_FullMethodName        = "/sso.SSO/SignIn"
	SSO_Check_FullMethodName         = "/sso.SSO/Check"
	SSO_LogoutCurrent_FullMethodName = "/sso.SSO/LogoutCurrent"
	SSO_LogoutAll_FullMethodName     = "/sso.SSO/LogoutAll"
	SSO_LogoutSession_FullMethodName = "/sso.SSO/LogoutSession"
)

// SSOClient is the client API for SSO service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type SSOClient interface {
	SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error)
	SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error)
	Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckResponse, error)
	LogoutCurrent(ctx context.Context, in *LogoutRequest, opts ...grpc.CallOption) (*LogoutResponse, error)
	LogoutAll(ctx context.Context, in *LogoutRequest, opts ...grpc.CallOption) (*LogoutResponse, error)
	LogoutSession(ctx context.Context, in *LogoutSessionRequest, opts ...grpc.CallOption) (*LogoutResponse, error)
}

type sSOClient struct {
	cc grpc.ClientConnInterface
}

func NewSSOClient(cc grpc.ClientConnInterface) SSOClient {
	return &sSOClient{cc}
}

func (c *sSOClient) SignUp(ctx context.Context, in *SignUpRequest, opts ...grpc.CallOption) (*SignUpResponse, error) {
	out := new(SignUpResponse)
	err := c.cc.Invoke(ctx, SSO_SignUp_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sSOClient) SignIn(ctx context.Context, in *SignInRequest, opts ...grpc.CallOption) (*SignInResponse, error) {
	out := new(SignInResponse)
	err := c.cc.Invoke(ctx, SSO_SignIn_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sSOClient) Check(ctx context.Context, in *CheckRequest, opts ...grpc.CallOption) (*CheckResponse, error) {
	out := new(CheckResponse)
	err := c.cc.Invoke(ctx, SSO_Check_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sSOClient) LogoutCurrent(ctx context.Context, in *LogoutRequest, opts ...grpc.CallOption) (*LogoutResponse, error) {
	out := new(LogoutResponse)
	err := c.cc.Invoke(ctx, SSO_LogoutCurrent_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sSOClient) LogoutAll(ctx context.Context, in *LogoutRequest, opts ...grpc.CallOption) (*LogoutResponse, error) {
	out := new(LogoutResponse)
	err := c.cc.Invoke(ctx, SSO_LogoutAll_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *sSOClient) LogoutSession(ctx context.Context, in *LogoutSessionRequest, opts ...grpc.CallOption) (*LogoutResponse, error) {
	out := new(LogoutResponse)
	err := c.cc.Invoke(ctx, SSO_LogoutSession_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SSOServer is the server API for SSO service.
// All implementations must embed UnimplementedSSOServer
// for forward compatibility
type SSOServer interface {
	SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error)
	SignIn(context.Context, *SignInRequest) (*SignInResponse, error)
	Check(context.Context, *CheckRequest) (*CheckResponse, error)
	LogoutCurrent(context.Context, *LogoutRequest) (*LogoutResponse, error)
	LogoutAll(context.Context, *LogoutRequest) (*LogoutResponse, error)
	LogoutSession(context.Context, *LogoutSessionRequest) (*LogoutResponse, error)
	mustEmbedUnimplementedSSOServer()
}

// UnimplementedSSOServer must be embedded to have forward compatible implementations.
type UnimplementedSSOServer struct {
}

func (UnimplementedSSOServer) SignUp(context.Context, *SignUpRequest) (*SignUpResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignUp not implemented")
}
func (UnimplementedSSOServer) SignIn(context.Context, *SignInRequest) (*SignInResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignIn not implemented")
}
func (UnimplementedSSOServer) Check(context.Context, *CheckRequest) (*CheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Check not implemented")
}
func (UnimplementedSSOServer) LogoutCurrent(context.Context, *LogoutRequest) (*LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LogoutCurrent not implemented")
}
func (UnimplementedSSOServer) LogoutAll(context.Context, *LogoutRequest) (*LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LogoutAll not implemented")
}
func (UnimplementedSSOServer) LogoutSession(context.Context, *LogoutSessionRequest) (*LogoutResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LogoutSession not implemented")
}
func (UnimplementedSSOServer) mustEmbedUnimplementedSSOServer() {}

// UnsafeSSOServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to SSOServer will
// result in compilation errors.
type UnsafeSSOServer interface {
	mustEmbedUnimplementedSSOServer()
}

func RegisterSSOServer(s grpc.ServiceRegistrar, srv SSOServer) {
	s.RegisterService(&SSO_ServiceDesc, srv)
}

func _SSO_SignUp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignUpRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).SignUp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_SignUp_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).SignUp(ctx, req.(*SignUpRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SSO_SignIn_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignInRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).SignIn(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_SignIn_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).SignIn(ctx, req.(*SignInRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SSO_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_Check_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).Check(ctx, req.(*CheckRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SSO_LogoutCurrent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogoutRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).LogoutCurrent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_LogoutCurrent_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).LogoutCurrent(ctx, req.(*LogoutRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SSO_LogoutAll_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogoutRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).LogoutAll(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_LogoutAll_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).LogoutAll(ctx, req.(*LogoutRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _SSO_LogoutSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LogoutSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SSOServer).LogoutSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: SSO_LogoutSession_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SSOServer).LogoutSession(ctx, req.(*LogoutSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// SSO_ServiceDesc is the grpc.ServiceDesc for SSO service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var SSO_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "sso.SSO",
	HandlerType: (*SSOServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignUp",
			Handler:    _SSO_SignUp_Handler,
		},
		{
			MethodName: "SignIn",
			Handler:    _SSO_SignIn_Handler,
		},
		{
			MethodName: "Check",
			Handler:    _SSO_Check_Handler,
		},
		{
			MethodName: "LogoutCurrent",
			Handler:    _SSO_LogoutCurrent_Handler,
		},
		{
			MethodName: "LogoutAll",
			Handler:    _SSO_LogoutAll_Handler,
		},
		{
			MethodName: "LogoutSession",
			Handler:    _SSO_LogoutSession_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/sso.proto",
}
