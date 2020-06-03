package main

import (
	"fmt"
	"github.com/universe-10th/chasqui"
	auth2 "github.com/universe-10th/chasqui-identity-protocols/auth"
	"github.com/universe-10th/chasqui-identity-protocols/auth/samples/realms"
	"github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
	"net"
)

type EchoProtocol struct {
	auth *auth2.AuthProtocol
}

func (protocol *EchoProtocol) Dependencies() protocols.Protocols {
	return protocols.Protocols{
		protocol.auth: true,
	}
}

func (protocol *EchoProtocol) Handlers() protocols.MessageHandlers {
	return protocol.auth.RequireAuthorizationAll(nil, protocols.MessageHandlers{
		"echo.ECHO": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			args := message.Args()
			kwArgs := message.KWArgs()
			if len(args) != 1 || len(kwArgs) != 0 {
				// noinspection GoUnhandledErrorResult
				attendant.Send("echo.INVALID_FORMAT", types.Args{"MSG", "Expected 1 positional (string) argument, and no keyword arguments"}, nil)
			} else if text, ok := args[0].(string); !ok {
				// noinspection GoUnhandledErrorResult
				attendant.Send("echo.INVALID_FORMAT", types.Args{"MSG", "The content must be a string"}, nil)
			} else {
				user := protocol.auth.Current(attendant)
				// noinspection GoUnhandledErrorResult
				attendant.Send("echo.ECHOED", types.Args{user.(*realms.DummyCredential).Identification(), text}, nil)
			}
		},
	})
}

// Nothing needed in these, since the users management is in the auth protocol

func (protocol *EchoProtocol) Started(server *chasqui.Server, addr *net.TCPAddr) {
	fmt.Println("Chat started for server:", server, addr)
}

func (protocol *EchoProtocol) AttendantStarted(server *chasqui.Server, attendant *chasqui.Attendant) {
	fmt.Println("Chat started for server and socket:", server, attendant)
}

func (protocol *EchoProtocol) AttendantStopped(server *chasqui.Server, attendant *chasqui.Attendant, stopType chasqui.AttendantStopType, err error) {
	fmt.Println("Chat stopped for server and socket:", server, attendant, stopType, err)
}

func (protocol *EchoProtocol) Stopped(server *chasqui.Server) {
	fmt.Println("Chat stopped for server:", server)
}

func NewChatProtocol(authProtocol *auth2.AuthProtocol) *EchoProtocol {
	if authProtocol.RealmsCount() != 1 {
		panic("the base authProtocol must have only one realm")
	}

	echoProtocol := &EchoProtocol{
		auth: authProtocol,
	}

	return echoProtocol
}
