package realms

import (
	"github.com/universe-10th/identity/credentials"
	"github.com/universe-10th/identity/realms"
	"github.com/universe-10th/identity/realms/login/activity"
	"github.com/universe-10th/identity/realms/login/password"
)

func MakeSamples() map[string]*DummyCredential {
	alicepw, _ := DummyHasher(0).Hash("alice1")
	bobpw, _ := DummyHasher(0).Hash("bob1")
	carlpw, _ := DummyHasher(0).Hash("carl1")
	dannypw, _ := DummyHasher(0).Hash("danny1")
	return map[string]*DummyCredential{
		"alice": &DummyCredential{"alice", alicepw},
		"bob":   &DummyCredential{"bob", bobpw},
		"carl":  &DummyCredential{"carl", carlpw},
		"danny": &DummyCredential{"danny", dannypw},
	}
}

var DummyRealm = realms.NewRealm(credentials.NewSource(NewDummyBroker(MakeSamples()), &DummyCredential{}), activity.ActivityStep(0), password.PasswordCheckingStep(0))
