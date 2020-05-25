package types

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/identity/credentials"
)

// Domain rules tell how a domain must handle users being
// logged in, in particular when several sessions are spawned.
// For security and privacy reasons, domain rules are applied
// only after a completely successful login (the whole pipeline
// succeeds).
type DomainRule uint8

// This custom criterion takes into account the credential that
// succeeded the login process, the generated qualified key (which
// is already unified) and the current server and attendants which
// have the same active credential in session. Two values are
// returned: A boolean value telling the session must be closed for
// the new connection, and a list of existing attendants -with the
// same credential in session, ideally- that should be "ghosted".
type DomainCustomCriterion func(credentials.Credential, QualifiedKey, *chasqui.Server,
	*chasqui.Attendant) (bool, []*chasqui.Attendant)

const (
	// Allows the same credential being logged multiple times.
	// This is seldom useful, perhaps for non-interactive
	// services (i.e. services where accounts do not interact
	// with each other).
	Multiple DomainRule = iota

	// Allows the same credential being logged only once.
	// Further successful logins are rejected. This is one
	// of the most useful approaches: further attempts will
	// be denied login until the current session terminates.
	SingleLocking

	// Allows the same credential being logged only once.
	// Further successful logins replace the current ones.
	// This is another of the most common approaches: the
	// current session will be replaced by new successful
	// logins (and thus will be disconnected), which could
	// be the same user attempting a new login after the
	// current connection or sessions became dangling or
	// somehow out of user's control.
	SingleGhosting

	// Allows using a custom criterion to treat new and
	// existing sessions for a given user / credential.
	// When a just-logging credential is already logged
	// in, a custom criterion will run. Such criterion
	// will take the (qualified) credential, its current
	// attendant, and all the other attendants this
	// credential is logged in. The criterion will return
	// the values:
	// - reject (error): If not null, the error will
	//   serve as rejection reason for the current login.
	// - ghost (attendants): An array of attendants to
	//   force-disconnect by ghosting (this means: kicking
	//   with reason: this account logged in other devices.
	//   Those attendants must belong to the currently
	//   logged attendants for this credential (attendants
	//   not satisfying that, will be ignored).
	Custom
)

// A domain keeps tracks of the currently logged in users.
// It also handles how the current and incoming sessions
// for a given credential will coexist. Domains are used
// inside an instance of an auth protocol, and thus are
// the same for each server bound to the protocol.
type Domain struct {
	// The chosen domain rule for this domain.
	rule DomainRule
	// If the rule is Custom, the custom criterion to
	// reject and/or ghost connections.
	criterion DomainCustomCriterion
	// A mean to get a "well known" pointer via a key.
	// this, to not spawn several repeated structures
	// for long time.
	unifiedKeys map[*chasqui.Server]map[QualifiedKey]*QualifiedKey
	// Given a well known pointer, gets a list of
	// attendants using the matching credential.
	sessions map[*chasqui.Server]map[*QualifiedKey][]*chasqui.Attendant
}

// For a given server this domain is used on, and a
// given key, returns a unified or "well known" value
// to be used as session's key (for a given attendant).
func (domain *Domain) loginKey(server *chasqui.Server, key QualifiedKey) *QualifiedKey {
	if _, ok := domain.unifiedKeys[server]; !ok {
		domain.unifiedKeys[server] = map[QualifiedKey]*QualifiedKey{}
	}
	if unified, ok := domain.unifiedKeys[server][key]; !ok {
		ptr := &key
		domain.unifiedKeys[server][key] = ptr
		return ptr
	} else {
		return unified
	}
}

// For a given server this domain is used on, and a
// given unified key, drops the key if no connections
// are referencing it in their sessions.
func (domain *Domain) logoutKey(server *chasqui.Server, key *QualifiedKey) {
	if sessions, ok := domain.sessions[server]; ok {
		if value, ok := sessions[key]; ok {
			if len(value) == 0 {
				delete(sessions, key)
				delete(domain.unifiedKeys[server], *key)
			}
		}
	}
}

// Checks the reject / ghost criterion for the incoming
// yet successful login attempt. It does not perform any
// change (in particular: ghost removal) in the current
// status of the domain.
func (domain *Domain) checkLanding(credential credentials.Credential, key QualifiedKey,
	server *chasqui.Server, attendant *chasqui.Attendant) (bool, []*chasqui.Attendant) {
	switch domain.rule {
	case Multiple:
		// Since multiple logins are allowed, then there
		// is nothing to do here: don't reject, don't ghost.
		return false, nil
	case SingleLocking:
		// One single login is allowed. Reject the incoming
		// connection if the credential is currently logged
		// in the server.
		if keys, ok := domain.unifiedKeys[server]; ok {
			if unified, ok := keys[key]; ok {
				if _, ok := domain.sessions[server][unified]; ok {
					return true, nil
				}
			}
		}
		return false, nil
	case SingleGhosting:
		// One single login is allowed. Accept the incoming
		// connection and ghost-kick existing connections
		// with the same credential.
		if keys, ok := domain.unifiedKeys[server]; ok {
			if unified, ok := keys[key]; ok {
				if currentSessions, ok := domain.sessions[server][unified]; ok {
					return false, currentSessions
				}
			}
		}
		return false, nil
	default:
		return domain.criterion(credential, key, server, attendant)
	}
}
