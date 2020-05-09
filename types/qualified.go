package types

import (
	"github.com/universe-10th/identity/credentials"
	"github.com/universe-10th/identity/credentials/traits/identified"
	"github.com/universe-10th/identity/credentials/traits/indexed"
	"github.com/universe-10th/identity/realms"
)

// A tracking session key, to consider many different
// credentials, which are actually the same, effectively
// the same at effects of logged-in users.
type QualifiedKey struct {
	key   interface{}
	realm *realms.Realm
}

// Creates a session key to track, for different credential
// instances, how many of them are the same (to tell when
// the logged credentials are the same).
func NewQualifiedKey(credential credentials.Credential, identifier interface{}, realm *realms.Realm) QualifiedKey {
	if identifiedCredential, ok := credential.(identified.Identified); ok {
		return QualifiedKey{
			key:   identifiedCredential.Identification(),
			realm: realm,
		}
	} else if indexedCredential, ok := credential.(indexed.Indexed); ok {
		return QualifiedKey{
			key:   indexedCredential.Index(),
			realm: realm,
		}
	} else {
		// This scenario is not recommended when the identifier is case-insensitive,
		// for duplicate entries may exist when different users log in with the
		// same account but using different casing.
		return QualifiedKey{
			key:   identifier,
			realm: realm,
		}
	}
}
