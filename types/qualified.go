package types

import (
	"github.com/universe-10th/identity/credentials"
	"github.com/universe-10th/identity/realm"
)

// A qualified credential knows the realm it
// comes from.
type QualifiedCredential struct {
	credentials.Credential
	realm *realm.Realm
}

// Returns the realm this credential belongs to.
func (logged *QualifiedCredential) Realm() *realm.Realm {
	return logged.realm
}

// Creates a new logged credential.
func NewLoggedCredential(credential credentials.Credential, realm *realm.Realm) *QualifiedCredential {
	return &QualifiedCredential{credential, realm}
}
