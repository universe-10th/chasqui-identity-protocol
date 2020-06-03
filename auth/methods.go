package auth

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui-identity-protocols/auth/events"
	types2 "github.com/universe-10th/chasqui-identity-protocols/auth/types"
	protocols "github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
	"github.com/universe-10th/identity/authreqs"
	"github.com/universe-10th/identity/credentials"
	"github.com/universe-10th/identity/realms"
)

// Requires authorization (login and perhaps an extra set
// of requirements) for a message handler. Returns a new
// wrapped message handler.
func (authProtocol *AuthProtocol) RequireAuthorization(
	requirement authreqs.AuthorizationRequirement,
	handler protocols.MessageHandler, options ...FallbackOption,
) protocols.MessageHandler {
	var notLoggedIn, permissionDenied protocols.MessageHandler
	for _, option := range options {
		notLoggedIn, permissionDenied = option(notLoggedIn, permissionDenied)
	}
	return authProtocol.fullWrap(handler, notLoggedIn, permissionDenied, requirement)
}

// Requires authorization for the message handlers in the
// map, by iterating and running RequireAuthorization on
// on each handler that satisfies the given condition.
func (authProtocol *AuthProtocol) RequireAuthorizationWhere(
	requirement authreqs.AuthorizationRequirement, handlers protocols.MessageHandlers,
	only func(string) bool, options ...FallbackOption,
) protocols.MessageHandlers {
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
func (authProtocol *AuthProtocol) RequireAuthorizationAll(
	requirement authreqs.AuthorizationRequirement, handlers protocols.MessageHandlers, options ...FallbackOption,
) protocols.MessageHandlers {
	return authProtocol.RequireAuthorizationWhere(requirement, handlers, func(string) bool { return true }, options...)
}

// Performs a logout on certain server/attendant, with a
// given type and an underlying reason.
func (authProtocol *AuthProtocol) Logout(server *chasqui.Server, attendant *chasqui.Attendant, logoutType, reason string) {
	if cred := authProtocol.getCredential(attendant); cred != nil {
		authProtocol.OnLogout().Trigger(server, attendant, cred, events.Before)
		if qualifiedKey := authProtocol.getQualifiedKey(attendant, true); qualifiedKey != nil {
			authProtocol.domain.RemoveSession(*qualifiedKey, server, attendant)
		}
		_ = attendant.Send(authProtocol.prefix+"logout.success", types.Args{logoutType, reason}, nil)
		authProtocol.OnLogout().Trigger(server, attendant, cred, events.After)
	}
}

// Gets the current user, if any.
func (authProtocol *AuthProtocol) Current(attendant *chasqui.Attendant) credentials.Credential {
	return authProtocol.getCredential(attendant)
}

// Given a server, enumerates all the current sessions
// telling their qualified key and their underlying socket.
// If the callback returns true, the iteration will stop.
func (authProtocol *AuthProtocol) EnumerateSessions(server *chasqui.Server, callback func(*types2.QualifiedKey, *chasqui.Attendant) bool) {
	authProtocol.domain.Enumerate(server, callback)
}

// Gets the count of realms in this auth protocol.
func (authProtocol *AuthProtocol) RealmsCount() int {
	return len(authProtocol.realms)
}

// Enumerates all the realms in this auth protocol.
// If the callback returns true, the iteration will stop.
func (authProtocol *AuthProtocol) EnumerateRealms(callback func(key string, realm *realms.Realm) bool) {
	for key, realm := range authProtocol.realms {
		if callback(key, realm) {
			return
		}
	}
}

// Gets a particular realm in this auth protocol.
// It also returns whether a realm was found.
func (authProtocol *AuthProtocol) Realm(key string) (*realms.Realm, bool) {
	realm, ok := authProtocol.realms[key]
	return realm, ok
}

// Returns the rule of the underlying domain.
func (authProtocol *AuthProtocol) DomainRule() types2.DomainRule {
	return authProtocol.domain.Rule()
}

// Returns the custom criterion of the underlying domain.
func (authProtocol *AuthProtocol) DomainCustomCriterion() types2.DomainCustomCriterion {
	return authProtocol.domain.CustomCriterion()
}
