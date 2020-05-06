package identity

import (
	"github.com/universe-10th/chasqui"
	"net"
)

// Nothing to be done when a server is started in this protocol layer.
// Realms will be already available and everything will be appropriately
// setup quite before everything starts here for a server.
func (authProtocol *AuthProtocol) Started(server *chasqui.Server, addr *net.TCPAddr) {}

// Nothing to be done when an attendant has just connected in this protocol
// layer. Other protocols will receive the same event and can add custom
// logic (e.g. to expect the connection performs a log in in some time),
func (authProtocol *AuthProtocol) AttendantStarted(server *chasqui.Server, attendant *chasqui.Attendant) {
}

// Nothing to be done when an attendant disconnects in this protocol layer.
// If by chance someone is tracking the logged credentials' status, this event
// will arrive there before it arrives to this auth protocol. User will have
// the chance to handle the issue right there.
func (authProtocol *AuthProtocol) AttendantStopped(server *chasqui.Server, attendant *chasqui.Attendant, stopType chasqui.AttendantStopType, err error) {
}

// Nothing to be done when a server is stopped in this protocol's funnel.
// If by chance someone is tracking the logged credentials' status, this
// event will arrive there before it arrives to this auth protocol. User
// will have the chance to handle the issue right there.
func (authProtocol *AuthProtocol) Stopped(server *chasqui.Server) {}
