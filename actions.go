package identity

import (
	protocols "github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/identity/authreqs"
)

// Requires authorization (login and perhaps an extra set
// of requirements) for a message handler. Returns a new
// wrapped message handler.
func (authProtocol *AuthProtocol) RequireAuthorization(requirement authreqs.AuthorizationRequirement,
	handler protocols.MessageHandler,
	options ...FallbackOption) protocols.MessageHandler {
	var notLoggedIn, permissionDenied protocols.MessageHandler
	for _, option := range options {
		notLoggedIn, permissionDenied = option(notLoggedIn, permissionDenied)
	}
	return authProtocol.fullWrap(handler, notLoggedIn, permissionDenied, requirement)
}

// Requires authorization for the message handlers in the
// map, by iterating and running RequireAuthorization on
// on each handler that satisfies the given condition.
func (authProtocol *AuthProtocol) RequireAuthorizationWhere(requirement authreqs.AuthorizationRequirement,
	handlers protocols.MessageHandlers,
	only func(string) bool,
	options ...FallbackOption) protocols.MessageHandlers {
	newHandlers := make(protocols.MessageHandlers)
	for key, handler := range handlers {
		if only(key) {
			newHandlers[key] = authProtocol.RequireAuthorization(requirement, handler, options...)
		} else {
			newHandlers[key] = handler
		}
	}
	return newHandlers
}

// Requires authorization for all the message handlers in
// the map, by iterating and running RequireAuthorization
// on each handler.
func (authProtocol *AuthProtocol) RequireAuthorizationAll(requirement authreqs.AuthorizationRequirement,
	handlers protocols.MessageHandlers,
	options ...FallbackOption) protocols.MessageHandlers {
	return authProtocol.RequireAuthorizationWhere(requirement, handlers, func(string) bool { return true }, options...)
}
