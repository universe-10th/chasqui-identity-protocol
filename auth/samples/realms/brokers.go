package realms

import (
	"errors"
	"github.com/universe-10th/identity/credentials"
)

var ErrBadValue = errors.New("expecting a string value")

type DummyBroker struct {
	users map[string]*DummyCredential
}

func (broker *DummyBroker) Allows(template credentials.Credential) bool {
	_, ok := template.(*DummyCredential)
	return ok
}

func (broker *DummyBroker) ByIdentifier(identifier interface{}, template credentials.Credential) (credentials.Credential, error) {
	if strIdentifier, ok := identifier.(string); !ok {
		return nil, ErrBadValue
	} else if result, ok := broker.users[strIdentifier]; !ok {
		return nil, nil
	} else {
		return result, nil
	}
}

func (broker *DummyBroker) ByIndex(index interface{}, template credentials.Credential) (credentials.Credential, error) {
	return broker.ByIdentifier(index, template)
}

func (broker *DummyBroker) Save(credential credentials.Credential) error {
	return nil
}

func NewDummyBroker(users map[string]*DummyCredential) *DummyBroker {
	return &DummyBroker{users: users}
}
