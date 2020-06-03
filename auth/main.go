package auth

import (
	"errors"
	"github.com/universe-10th/chasqui"
	types2 "github.com/universe-10th/chasqui-identity-protocols/auth/types"
	"github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
	"github.com/universe-10th/identity/realms"
)

var ErrRejectedByDomain = errors.New("rejected - already logged in")
var ErrMissingUnifiedKey = errors.New("missing unified key in context")

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
				} else if credential, err := currentRealm.Login(args[0], password); err == nil {
					qualifiedKey := types2.NewQualifiedKey(credential, args[0], currentRealm)
					reject, ghost := authProtocol.domain.CheckLanding(credential, qualifiedKey, server, attendant)

					for attendant := range ghost {
						authProtocol.Logout(server, attendant, "ghosted", "")
					}

					if reject {
						_ = attendant.Send(authProtocol.prefix+"login.rejected", nil, nil)
						authProtocol.OnLogin().Trigger(server, attendant, args[0], password, realmKey, credential, ErrRejectedByDomain)
					} else {
						authProtocol.setCredential(attendant, credential)
						unifiedKey := authProtocol.domain.AddSession(qualifiedKey, server, attendant)
						authProtocol.setQualifiedKey(attendant, unifiedKey)
						_ = attendant.Send(authProtocol.prefix+"login.success", nil, nil)
						authProtocol.OnLogin().Trigger(server, attendant, args[0], password, realmKey, credential, nil)
					}
				} else {
					message := "login failed: internal error"
					if err == realms.ErrLoginFailed {
						message = "login failed: mismatch"
					}
					_ = attendant.Send(authProtocol.prefix+"login.error", types.Args{message}, nil)
					authProtocol.OnLogin().Trigger(server, attendant, args[0], password, realmKey, credential, err)
				}
			}
		},
		authProtocol.prefix + "logout": authProtocol.fullWrap(func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			authProtocol.Logout(server, attendant, "graceful", "")
		}, authProtocol.notLoggedInHandler, nil, nil),
		authProtocol.prefix + "change-password": authProtocol.fullWrap(func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
			args := message.Args()
			if len(args) != 1 {
				_ = authProtocol.sendInvalidFormat(authProtocol.prefix+"change-password", "exactly one string argument must be supplied", attendant)
			} else if password, ok := args[0].(string); !ok {
				_ = authProtocol.sendInvalidFormat(authProtocol.prefix+"change-password", "exactly one string argument must be supplied", attendant)
			} else {
				credential := authProtocol.getCredential(attendant)
				if unifiedKey := authProtocol.getQualifiedKey(attendant, false); unifiedKey != nil {
					realm := unifiedKey.Realm()
					if err := realm.SetPassword(credential, password); err != nil {
						_ = attendant.Send(authProtocol.prefix+"change-password.error", nil, nil)
						authProtocol.OnPasswordChange().Trigger(server, attendant, credential, err)
					} else {
						_ = attendant.Send(authProtocol.prefix+"change-password.success", nil, nil)
						authProtocol.OnPasswordChange().Trigger(server, attendant, credential, nil)
					}
				} else {
					_ = attendant.Send(authProtocol.prefix+"change-password.error", nil, nil)
					authProtocol.OnPasswordChange().Trigger(server, attendant, credential, ErrMissingUnifiedKey)
				}
			}
		}, authProtocol.notLoggedInHandler, nil, nil),
	}
}

var _ protocols.Protocol = &AuthProtocol{}
