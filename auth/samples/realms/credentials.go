package realms

import "github.com/universe-10th/identity/hashing"

type DummyCredential struct {
	username interface{}
	password string
}

func (credential *DummyCredential) HashedPassword() string {
	return credential.password
}

func (credential *DummyCredential) SetHashedPassword(password string) {
	credential.password = password
}

func (credential *DummyCredential) Hasher() hashing.HashingEngine {
	return DummyHasher(0)
}

func (credential *DummyCredential) Identification() interface{} {
	return credential.username
}
