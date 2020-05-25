package identity

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
)

// Auth protocols do not have dependencies.
func (authProtocol *AuthProtocol) Dependencies() protocols.Protocols {
	return nil
}

// Auth protocols define their own handlers, which involves a custom
// namespace to be used.
func (authProtocol *AuthProtocol) Handlers() protocols.MessageHandlers {
	return protocols.MessageHandlers{
		authProtocol.prefix + "login": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			args := message.Args()
			if len(args) != 3 {
				_ = authProtocol.sendInvalidFormat(authProtocol.prefix+"login", "expected 3 args: identifier, password, realm", attendant)
			} else {
				if password, ok := args[1].(string); !ok {
					_ = authProtocol.sendInvalidFormat(authProtocol.prefix+"login", "password argument must be a string", attendant)
				} else if realmKey, ok := args[2].(string); !ok {
					_ = authProtocol.sendInvalidFormat(authProtocol.prefix+"login", "realm argument must be a string", attendant)
				} else if currentRealm, ok := authProtocol.realms[realmKey]; !ok {
					_ = authProtocol.sendInvalidFormat(authProtocol.prefix+"login", "realm is invalid", attendant)
				} else if credential, err := currentRealm.Login(args[0], password); err != nil {
					authProtocol.setCredential(attendant, credential)
					// TODO use the domain here to condition the login process.
					authProtocol.OnLogin().Trigger(args[0], password, realmKey, credential, err)
				} else {
					authProtocol.OnLogin().Trigger(args[0], password, realmKey, credential, err)
				}
			}
		},
		authProtocol.prefix + "logout": authProtocol.fullWrap(func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			// TODO Implement, including using the domain.
		}, authProtocol.notLoggedInHandler, nil, nil),
		authProtocol.prefix + "change-password": authProtocol.fullWrap(func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			// TODO Implement.
		}, authProtocol.notLoggedInHandler, nil, nil),
	}
}

var _ protocols.Protocol = &AuthProtocol{}
