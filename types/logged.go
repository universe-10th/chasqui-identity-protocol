package types

import (
	"github.com/universe-10th/identity/credentials"
	"github.com/universe-10th/identity/realms"
)

// A logged credential also remembers the realm
// it came from.
type LoggedCredential struct {
	credentials.Credential
	realm *realms.Realm
}

// Returns the realm of this logged credential.
func (loggedCredential *LoggedCredential) Realm() *realms.Realm {
	return loggedCredential.realm
}

// Returns the underlying credential of this
// logged credential.
func (loggedCredential *LoggedCredential) Unwrap() credentials.Credential {
	return loggedCredential.Credential
}

// Wraps a credential with its realm into into a
// logged credential.
func NewLoggedCredential(credential credentials.Credential, realm *realms.Realm) *LoggedCredential {
	return &LoggedCredential{
		Credential: credential,
		realm:      realm,
	}
}
