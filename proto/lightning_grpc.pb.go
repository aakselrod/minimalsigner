// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

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

// LightningClient is the client API for Lightning service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type LightningClient interface {
	// lncli: `signmessage`
	//SignMessage signs a message with this node's private key. The returned
	//signature string is `zbase32` encoded and pubkey recoverable, meaning that
	//only the message digest and signature are needed for verification.
	SignMessage(ctx context.Context, in *SignMessageRequest, opts ...grpc.CallOption) (*SignMessageResponse, error)
	// lncli: `getinfo`
	//GetInfo returns general information concerning the lightning node including
	//it's identity pubkey, alias, the chains it is connected to, and information
	//concerning the number of open+pending channels.
	GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error)
	// lncli: `stop`
	//StopDaemon will send a shutdown request to the interrupt handler, triggering
	//a graceful shutdown of the daemon.
	StopDaemon(ctx context.Context, in *StopRequest, opts ...grpc.CallOption) (*StopResponse, error)
	// lncli: `debuglevel`
	//DebugLevel allows a caller to programmatically set the logging verbosity of
	//lnd. The logging can be targeted according to a coarse daemon-wide logging
	//level, or in a granular fashion to specify the logging for a target
	//sub-system.
	DebugLevel(ctx context.Context, in *DebugLevelRequest, opts ...grpc.CallOption) (*DebugLevelResponse, error)
	// lncli: `bakemacaroon`
	//BakeMacaroon allows the creation of a new macaroon with custom read and
	//write permissions. No first-party caveats are added since this can be done
	//offline.
	BakeMacaroon(ctx context.Context, in *BakeMacaroonRequest, opts ...grpc.CallOption) (*BakeMacaroonResponse, error)
	// lncli: `listmacaroonids`
	//ListMacaroonIDs returns all root key IDs that are in use.
	ListMacaroonIDs(ctx context.Context, in *ListMacaroonIDsRequest, opts ...grpc.CallOption) (*ListMacaroonIDsResponse, error)
	// lncli: `deletemacaroonid`
	//DeleteMacaroonID deletes the specified macaroon ID and invalidates all
	//macaroons derived from that ID.
	DeleteMacaroonID(ctx context.Context, in *DeleteMacaroonIDRequest, opts ...grpc.CallOption) (*DeleteMacaroonIDResponse, error)
	// lncli: `listpermissions`
	//ListPermissions lists all RPC method URIs and their required macaroon
	//permissions to access them.
	ListPermissions(ctx context.Context, in *ListPermissionsRequest, opts ...grpc.CallOption) (*ListPermissionsResponse, error)
	//
	//CheckMacaroonPermissions checks whether a request follows the constraints
	//imposed on the macaroon and that the macaroon is authorized to follow the
	//provided permissions.
	CheckMacaroonPermissions(ctx context.Context, in *CheckMacPermRequest, opts ...grpc.CallOption) (*CheckMacPermResponse, error)
}

type lightningClient struct {
	cc grpc.ClientConnInterface
}

func NewLightningClient(cc grpc.ClientConnInterface) LightningClient {
	return &lightningClient{cc}
}

func (c *lightningClient) SignMessage(ctx context.Context, in *SignMessageRequest, opts ...grpc.CallOption) (*SignMessageResponse, error) {
	out := new(SignMessageResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/SignMessage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error) {
	out := new(GetInfoResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/GetInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) StopDaemon(ctx context.Context, in *StopRequest, opts ...grpc.CallOption) (*StopResponse, error) {
	out := new(StopResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/StopDaemon", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) DebugLevel(ctx context.Context, in *DebugLevelRequest, opts ...grpc.CallOption) (*DebugLevelResponse, error) {
	out := new(DebugLevelResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/DebugLevel", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) BakeMacaroon(ctx context.Context, in *BakeMacaroonRequest, opts ...grpc.CallOption) (*BakeMacaroonResponse, error) {
	out := new(BakeMacaroonResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/BakeMacaroon", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) ListMacaroonIDs(ctx context.Context, in *ListMacaroonIDsRequest, opts ...grpc.CallOption) (*ListMacaroonIDsResponse, error) {
	out := new(ListMacaroonIDsResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/ListMacaroonIDs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) DeleteMacaroonID(ctx context.Context, in *DeleteMacaroonIDRequest, opts ...grpc.CallOption) (*DeleteMacaroonIDResponse, error) {
	out := new(DeleteMacaroonIDResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/DeleteMacaroonID", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) ListPermissions(ctx context.Context, in *ListPermissionsRequest, opts ...grpc.CallOption) (*ListPermissionsResponse, error) {
	out := new(ListPermissionsResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/ListPermissions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *lightningClient) CheckMacaroonPermissions(ctx context.Context, in *CheckMacPermRequest, opts ...grpc.CallOption) (*CheckMacPermResponse, error) {
	out := new(CheckMacPermResponse)
	err := c.cc.Invoke(ctx, "/proto.Lightning/CheckMacaroonPermissions", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LightningServer is the server API for Lightning service.
// All implementations must embed UnimplementedLightningServer
// for forward compatibility
type LightningServer interface {
	// lncli: `signmessage`
	//SignMessage signs a message with this node's private key. The returned
	//signature string is `zbase32` encoded and pubkey recoverable, meaning that
	//only the message digest and signature are needed for verification.
	SignMessage(context.Context, *SignMessageRequest) (*SignMessageResponse, error)
	// lncli: `getinfo`
	//GetInfo returns general information concerning the lightning node including
	//it's identity pubkey, alias, the chains it is connected to, and information
	//concerning the number of open+pending channels.
	GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error)
	// lncli: `stop`
	//StopDaemon will send a shutdown request to the interrupt handler, triggering
	//a graceful shutdown of the daemon.
	StopDaemon(context.Context, *StopRequest) (*StopResponse, error)
	// lncli: `debuglevel`
	//DebugLevel allows a caller to programmatically set the logging verbosity of
	//lnd. The logging can be targeted according to a coarse daemon-wide logging
	//level, or in a granular fashion to specify the logging for a target
	//sub-system.
	DebugLevel(context.Context, *DebugLevelRequest) (*DebugLevelResponse, error)
	// lncli: `bakemacaroon`
	//BakeMacaroon allows the creation of a new macaroon with custom read and
	//write permissions. No first-party caveats are added since this can be done
	//offline.
	BakeMacaroon(context.Context, *BakeMacaroonRequest) (*BakeMacaroonResponse, error)
	// lncli: `listmacaroonids`
	//ListMacaroonIDs returns all root key IDs that are in use.
	ListMacaroonIDs(context.Context, *ListMacaroonIDsRequest) (*ListMacaroonIDsResponse, error)
	// lncli: `deletemacaroonid`
	//DeleteMacaroonID deletes the specified macaroon ID and invalidates all
	//macaroons derived from that ID.
	DeleteMacaroonID(context.Context, *DeleteMacaroonIDRequest) (*DeleteMacaroonIDResponse, error)
	// lncli: `listpermissions`
	//ListPermissions lists all RPC method URIs and their required macaroon
	//permissions to access them.
	ListPermissions(context.Context, *ListPermissionsRequest) (*ListPermissionsResponse, error)
	//
	//CheckMacaroonPermissions checks whether a request follows the constraints
	//imposed on the macaroon and that the macaroon is authorized to follow the
	//provided permissions.
	CheckMacaroonPermissions(context.Context, *CheckMacPermRequest) (*CheckMacPermResponse, error)
	mustEmbedUnimplementedLightningServer()
}

// UnimplementedLightningServer must be embedded to have forward compatible implementations.
type UnimplementedLightningServer struct {
}

func (UnimplementedLightningServer) SignMessage(context.Context, *SignMessageRequest) (*SignMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignMessage not implemented")
}
func (UnimplementedLightningServer) GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetInfo not implemented")
}
func (UnimplementedLightningServer) StopDaemon(context.Context, *StopRequest) (*StopResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method StopDaemon not implemented")
}
func (UnimplementedLightningServer) DebugLevel(context.Context, *DebugLevelRequest) (*DebugLevelResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DebugLevel not implemented")
}
func (UnimplementedLightningServer) BakeMacaroon(context.Context, *BakeMacaroonRequest) (*BakeMacaroonResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BakeMacaroon not implemented")
}
func (UnimplementedLightningServer) ListMacaroonIDs(context.Context, *ListMacaroonIDsRequest) (*ListMacaroonIDsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListMacaroonIDs not implemented")
}
func (UnimplementedLightningServer) DeleteMacaroonID(context.Context, *DeleteMacaroonIDRequest) (*DeleteMacaroonIDResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteMacaroonID not implemented")
}
func (UnimplementedLightningServer) ListPermissions(context.Context, *ListPermissionsRequest) (*ListPermissionsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListPermissions not implemented")
}
func (UnimplementedLightningServer) CheckMacaroonPermissions(context.Context, *CheckMacPermRequest) (*CheckMacPermResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckMacaroonPermissions not implemented")
}
func (UnimplementedLightningServer) mustEmbedUnimplementedLightningServer() {}

// UnsafeLightningServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to LightningServer will
// result in compilation errors.
type UnsafeLightningServer interface {
	mustEmbedUnimplementedLightningServer()
}

func RegisterLightningServer(s grpc.ServiceRegistrar, srv LightningServer) {
	s.RegisterService(&Lightning_ServiceDesc, srv)
}

func _Lightning_SignMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignMessageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).SignMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/SignMessage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).SignMessage(ctx, req.(*SignMessageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_GetInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).GetInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/GetInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).GetInfo(ctx, req.(*GetInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_StopDaemon_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).StopDaemon(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/StopDaemon",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).StopDaemon(ctx, req.(*StopRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_DebugLevel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DebugLevelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).DebugLevel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/DebugLevel",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).DebugLevel(ctx, req.(*DebugLevelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_BakeMacaroon_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BakeMacaroonRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).BakeMacaroon(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/BakeMacaroon",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).BakeMacaroon(ctx, req.(*BakeMacaroonRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_ListMacaroonIDs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListMacaroonIDsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).ListMacaroonIDs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/ListMacaroonIDs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).ListMacaroonIDs(ctx, req.(*ListMacaroonIDsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_DeleteMacaroonID_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteMacaroonIDRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).DeleteMacaroonID(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/DeleteMacaroonID",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).DeleteMacaroonID(ctx, req.(*DeleteMacaroonIDRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_ListPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListPermissionsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).ListPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/ListPermissions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).ListPermissions(ctx, req.(*ListPermissionsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Lightning_CheckMacaroonPermissions_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckMacPermRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightningServer).CheckMacaroonPermissions(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.Lightning/CheckMacaroonPermissions",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightningServer).CheckMacaroonPermissions(ctx, req.(*CheckMacPermRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Lightning_ServiceDesc is the grpc.ServiceDesc for Lightning service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Lightning_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Lightning",
	HandlerType: (*LightningServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignMessage",
			Handler:    _Lightning_SignMessage_Handler,
		},
		{
			MethodName: "GetInfo",
			Handler:    _Lightning_GetInfo_Handler,
		},
		{
			MethodName: "StopDaemon",
			Handler:    _Lightning_StopDaemon_Handler,
		},
		{
			MethodName: "DebugLevel",
			Handler:    _Lightning_DebugLevel_Handler,
		},
		{
			MethodName: "BakeMacaroon",
			Handler:    _Lightning_BakeMacaroon_Handler,
		},
		{
			MethodName: "ListMacaroonIDs",
			Handler:    _Lightning_ListMacaroonIDs_Handler,
		},
		{
			MethodName: "DeleteMacaroonID",
			Handler:    _Lightning_DeleteMacaroonID_Handler,
		},
		{
			MethodName: "ListPermissions",
			Handler:    _Lightning_ListPermissions_Handler,
		},
		{
			MethodName: "CheckMacaroonPermissions",
			Handler:    _Lightning_CheckMacaroonPermissions_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "lightning.proto",
}
