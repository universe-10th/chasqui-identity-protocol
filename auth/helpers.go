package identity

import (
	"github.com/universe-10th/chasqui"
	protocols "github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/chasqui/types"
	"github.com/universe-10th/identity/authreqs"
	"github.com/universe-10th/identity/credentials"
)

// Sends an error message to the client socket.
func (authProtocol *AuthProtocol) sendInvalidFormat(command, detail string, attendant *chasqui.Attendant) error {
	return attendant.Send(authProtocol.prefix+"invalid", types.Args{command, detail}, nil)
}

// Ensures both callbacks to be non-nil, using the
// default callbacks to replace them, per-case.
func (authProtocol *AuthProtocol) ensureCallbacks(notLoggedIn, permissionDenied protocols.MessageHandler) (protocols.MessageHandler, protocols.MessageHandler) {
	if notLoggedIn == nil {
		notLoggedIn = authProtocol.notLoggedInHandler
	}
	if permissionDenied == nil {
		permissionDenied = authProtocol.permissionDeniedHandler
	}
	return notLoggedIn, permissionDenied
}

// Gets the current credential in a given attendant.
// Returns nil if the current user context key does
// not have any credential for that socket.
func (authProtocol *AuthProtocol) getCredential(attendant *chasqui.Attendant) credentials.Credential {
	if value, ok := attendant.Context(authProtocol.currentUserContextKey); !ok {
		return nil
	} else if credential, ok := value.(credentials.Credential); !ok {
		return nil
	} else {
		return credential
	}
}

// Removes the current credential from a given attendant.
func (authProtocol *AuthProtocol) removeCredential(attendant *chasqui.Attendant) {
	attendant.RemoveContext(authProtocol.currentUserContextKey)
}

// Sets the current credential in a given attendant.
func (authProtocol *AuthProtocol) setCredential(attendant *chasqui.Attendant, credential credentials.Credential) {
	attendant.SetContext(authProtocol.currentUserContextKey, credential)
}

// Fully wraps a handler inside an authorization flow,
// involving both login and authorization requirement.
func (authProtocol *AuthProtocol) fullWrap(handler, notLoggedIn, permissionDenied protocols.MessageHandler,
	requirement authreqs.AuthorizationRequirement) protocols.MessageHandler {
	notLoggedIn, permissionDenied = authProtocol.ensureCallbacks(notLoggedIn, permissionDenied)
	return func(server *chasqui.Server, attendant *chasqui.Attendant, message types.Message) {
		if credential := authProtocol.getCredential(attendant); credential == nil {
			notLoggedIn(server, attendant, message)
		} else if requirement != nil && !requirement.SatisfiedBy(credential) {
			permissionDenied(server, attendant, message)
		} else {
			handler(server, attendant, message)
		}
	}
}
