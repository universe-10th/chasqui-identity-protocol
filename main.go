package identity

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/chasqui-protocols"
	"github.com/universe-10th/identity/realm"
	"net"
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
	realms map[string]*realm.Realm
}

// Auth protocols do not have dependencies.
func (authProtocol *AuthProtocol) Dependencies() protocols.Protocol {
	return nil
}

// Auth protocols define their own handlers, which involves a custom
// namespace to be used.
func (authProtocol *AuthProtocol) Handlers() protocols.MessageHandlers {
	// TODO implement this.
	return nil
}

func (authProtocol *AuthProtocol) Started(server *chasqui.Server, addr *net.TCPAddr) {
	// TODO consider if a custom callback should be used, or not, to handle this.
	// TODO after that, put an appropriate docstring to this method.
}

func (authProtocol *AuthProtocol) AttendantStarted(server *chasqui.Server, attendant *chasqui.Attendant) {
	// TODO consider if a custom callback should be used, or not, to handle this.
	// TODO after that, put an appropriate docstring to this method.
}

func (authProtocol *AuthProtocol) AttendantStopped(server *chasqui.Server, attendant *chasqui.Attendant, stopType chasqui.AttendantStopType, err error) {
	// TODO consider if a custom callback should be used, or not, to handle this.
	// TODO after that, put an appropriate docstring to this method.
}

func (authProtocol *AuthProtocol) Stopped(server *chasqui.Server) {
	// TODO consider if a custom callback should be used, or not, to handle this.
	// TODO after that, put an appropriate docstring to this method.
}

// TODO implement the auth-wrappers and permissions-wrappers for one, several, and all handlers.
