package auth

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui-identity-protocols/auth/events"
	"github.com/universe-10th/chasqui-identity-protocols/auth/types"
	protocols "github.com/universe-10th/chasqui-protocols"
	types2 "github.com/universe-10th/chasqui/types"
	"github.com/universe-10th/identity/realms"
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
	// A pre-computed string: "{prefix}key", like "auth.key".
	// Users will not set this field.
	currentQualifiedKeyContextKey string
	// All the available login realms for login and permission check.
	// Realms are created beforehand (on protocol instantiation).
	realms map[string]*realms.Realm
	// The domain for this authentication protocol.
	domain *types.Domain
	// "Unauthorized" callbacks trigger when a login or an auth
	// requirement check fails.
	// A default handler for when a log-in is required.
	notLoggedInHandler protocols.MessageHandler
	// A default handler for when a permission is denied.
	permissionDeniedHandler protocols.MessageHandler
}

// By default, the domain will be of a single-locking
// type, and the notLoggedIn / permissionDenied handlers
// will just send standard messages to the attendants.
func NewAuthProtocol(realms map[string]*realms.Realm, options ...AuthOption) *AuthProtocol {
	protocol := &AuthProtocol{
		WithAuthEvents: events.NewWithAuthEvents(),
		realms:         realms,
		prefix:         "auth",
		domain:         types.NewDomain(types.SingleLocking, nil),
	}

	protocol.notLoggedInHandler = func(server *chasqui.Server, attendant *chasqui.Attendant, message types2.Message) {
		// noinspection GoUnhandledErrorResult
		attendant.Send(protocol.prefix+"login-required", nil, nil)
	}
	protocol.permissionDeniedHandler = func(server *chasqui.Server, attendant *chasqui.Attendant, message types2.Message) {
		// noinspection GoUnhandledErrorResult
		attendant.Send(protocol.prefix+"permission-denied", nil, nil)
	}

	for _, option := range options {
		option(protocol)
	}

	if protocol.prefix != "" {
		protocol.currentUserContextKey = protocol.prefix + ".user"
		protocol.currentQualifiedKeyContextKey = protocol.prefix + ".key"
		protocol.prefix = protocol.prefix + "."
	} else {
		protocol.currentUserContextKey = "user"
		protocol.currentQualifiedKeyContextKey = "key"
	}
}
