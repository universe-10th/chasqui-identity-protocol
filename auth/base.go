package identity

import (
	"github.com/universe-10th/chasqui-identity-protocols/auth/events"
	protocols "github.com/universe-10th/chasqui-protocols"
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
	// All the available login realms for login and permission check.
	// Realms are created beforehand (on protocol instantiation).
	realms map[string]*realms.Realm
	// "Unauthorized" callbacks trigger when a login or an auth
	// requirement check fails.
	// A default handler for when a log-in is required.
	notLoggedInHandler protocols.MessageHandler
	// A default handler for when a permission is denied.
	permissionDeniedHandler protocols.MessageHandler
}
