package main

import (
	"fmt"
	"github.com/universe-10th/chasqui"
	auth2 "github.com/universe-10th/chasqui-identity-protocols/auth"
	"github.com/universe-10th/chasqui-identity-protocols/auth/events"
	"github.com/universe-10th/chasqui-identity-protocols/auth/samples/realms"
	types2 "github.com/universe-10th/chasqui-identity-protocols/auth/types"
	"github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
	"github.com/universe-10th/identity/credentials"
	"github.com/universe-10th/identity/credentials/traits/identified"
	"net"
	"strings"
)

type ChatProtocol struct {
	auth     *auth2.AuthProtocol
	sessions map[*chasqui.Server]map[string]*chasqui.Attendant
}

func (protocol *ChatProtocol) Dependencies() protocols.Protocols {
	return protocols.Protocols{
		protocol.auth: true,
	}
}

func (protocol *ChatProtocol) Handlers() protocols.MessageHandlers {
	return protocol.auth.RequireAuthorizationAll(nil, protocols.MessageHandlers{
		"chat.MSG": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			args := message.Args()
			kwArgs := message.KWArgs()
			if len(args) != 1 || len(kwArgs) != 0 {
				// noinspection GoUnhandledErrorResult
				attendant.Send("chat.INVALID_FORMAT", types.Args{"MSG", "Expected 1 positional (string) argument, and no keyword arguments"}, nil)
			} else if text, ok := args[0].(string); !ok {
				// noinspection GoUnhandledErrorResult
				attendant.Send("chat.INVALID_FORMAT", types.Args{"MSG", "The content must be a string"}, nil)
			} else {
				user := protocol.auth.Current(attendant)
				for _, attendant2 := range protocol.sessions[server] {
					// noinspection GoUnhandledErrorResult
					attendant2.Send("chat.MSG_RECEIVED", types.Args{user.(*realms.DummyCredential).Identification(), text}, nil)
				}
			}
		},
		"chat.PMSG": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			args := message.Args()
			kwArgs := message.KWArgs()
			if len(args) != 2 || len(kwArgs) != 0 {
				// noinspection GoUnhandledErrorResult
				attendant.Send("INVALID_FORMAT", types.Args{"PMSG", "Expected 2 positional (string) arguments: user and content, and no keyword arguments"}, nil)
			} else if targetName, ok := args[0].(string); !ok {
				// noinspection GoUnhandledErrorResult
				attendant.Send("INVALID_FORMAT", types.Args{"PMSG", "The target username must be a string"}, nil)
			} else if text, ok := args[1].(string); !ok {
				// noinspection GoUnhandledErrorResult
				attendant.Send("INVALID_FORMAT", types.Args{"PMSG", "The content must be a string"}, nil)
			} else if attendant2, ok := protocol.sessions[server][strings.ToLower(targetName)]; !ok {
				// noinspection GoUnhandledErrorResult
				attendant.Send("INVALID_TARGET", types.Args{"PMSG", "The target is not logged in"}, nil)
			} else {
				source := protocol.auth.Current(attendant)
				// noinspection GoUnhandledErrorResult
				attendant2.Send("MSG_RECEIVED", types.Args{source.(identified.Identified).Identification().(string), text}, nil)
			}
		},
	})
}

// Nothing needed in these, since the users management is in the auth protocol

func (protocol *ChatProtocol) Started(server *chasqui.Server, addr *net.TCPAddr) {
	fmt.Println("Chat started for server:", server, addr)
}

func (protocol *ChatProtocol) AttendantStarted(server *chasqui.Server, attendant *chasqui.Attendant) {
	fmt.Println("Chat started for server and socket:", server, attendant)
}

func (protocol *ChatProtocol) AttendantStopped(server *chasqui.Server, attendant *chasqui.Attendant, stopType chasqui.AttendantStopType, err error) {
	fmt.Println("Chat stopped for server and socket:", server, attendant, stopType, err)
}

func (protocol *ChatProtocol) Stopped(server *chasqui.Server) {
	fmt.Println("Chat stopped for server:", server)
}

func NewChatProtocol(authProtocol *auth2.AuthProtocol) *ChatProtocol {
	if authProtocol.RealmsCount() != 1 {
		panic("the base authProtocol must have only one realm")
	}
	if authProtocol.DomainRule() != types2.SingleLocking && authProtocol.DomainRule() != types2.SingleGhosting {
		panic("the underlying domain must be single-based")
	}

	chatProtocol := &ChatProtocol{
		auth:     authProtocol,
		sessions: map[*chasqui.Server]map[string]*chasqui.Attendant{},
	}

	authProtocol.OnLogin().Register(func(server *chasqui.Server, attendant *chasqui.Attendant, identifier interface{}, password string, realm string, credential credentials.Credential, err error) {
		if err != nil {
			return
		}

		var sessions map[string]*chasqui.Attendant
		var ok bool

		if sessions, ok = chatProtocol.sessions[server]; !ok {
			sessions = map[string]*chasqui.Attendant{}
			chatProtocol.sessions[server] = sessions
		}

		for _, attendant2 := range sessions {
			// noinspection GoUnhandledErrorResult
			attendant2.Send("chat.JOIN", types.Args{credential.(identified.Identified).Identification().(string)}, nil)
		}

		sessions[credential.(identified.Identified).Identification().(string)] = attendant
	})
	authProtocol.OnLogout().Register(func(server *chasqui.Server, attendant *chasqui.Attendant, credential credentials.Credential, stage events.LogoutStage) {
		if stage == events.Before {
			if sessions, ok := chatProtocol.sessions[server]; ok {
				delete(sessions, credential.(identified.Identified).Identification().(string))
			}
		} else if stage == events.After {
			for _, attendant2 := range chatProtocol.sessions[server] {
				// noinspection GoUnhandledErrorResult
				attendant2.Send("chat.PART", types.Args{credential.(identified.Identified).Identification().(string)}, nil)
			}
		}
	})

	return chatProtocol
}
