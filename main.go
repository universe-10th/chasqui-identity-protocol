package identity

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui-identity-protocol/events"
	"github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
	"github.com/universe-10th/identity/realm"
)

// An auth protocol provides handlers for several
// commands which end in the interaction with a
// realm. Available interactions are already
// documented in github.com/universe-10th/identity
// repository, and implemented here as a bunch of
// protocol messages handlers.
//
// This protocol also serves as dependency to
// other protocols, mainly to require authentication
// or permissions on certain command handler(s).
type AuthProtocol struct {
	// Events that trigger actions on credentials being
	// logged-in, logged-out or password-changed.
	events.WithAuthEvents

	// A prefix like "auth.", computed from the given namespace.
	// If the namespace is empty, the prefix will be "", not ".".
	prefix string
	// A pre-computed string: "{prefix}user", like "auth.user".
	// Users will not set this field.
	currentUserContextKey string
	// All the available login realms for login and permission check.
	// Realms are created beforehand (on protocol instantiation).
	realms map[string]*realm.Realm
	// "Unauthorized" callbacks trigger when a login or an auth
	// requirement check fails.
	// A default handler for when a log-in is required.
	notLoggedInHandler protocols.MessageHandler
	// A default handler for when a permission is denied.
	permissionDeniedHandler protocols.MessageHandler
}

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
					authProtocol.OnLogin().Trigger(args[0], password, realmKey, credential, err)
				} else {
					authProtocol.OnLogin().Trigger(args[0], password, realmKey, credential, err)
				}
			}
		},
		authProtocol.prefix + "logout": authProtocol.fullWrap(func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {

		}, authProtocol.notLoggedInHandler, nil, nil),
		authProtocol.prefix + "change-password": authProtocol.fullWrap(func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {

		}, authProtocol.notLoggedInHandler, nil, nil),
		authProtocol.prefix + "recover-start": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {

		},
		authProtocol.prefix + "recover-cancel": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {

		},
		authProtocol.prefix + "recover-confirm": func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {

		},
	}
}

var _ protocols.Protocol = &AuthProtocol{}
