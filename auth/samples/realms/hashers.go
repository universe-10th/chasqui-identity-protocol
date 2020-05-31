package realms

import (
	"errors"
	"fmt"
)

type DummyHasher uint

func (hasher DummyHasher) Name() string { return fmt.Sprintf("dummy[%d]", hasher) }
func (hasher DummyHasher) Hash(password string) (string, error) {
	return fmt.Sprintf("Hashed[%s, %d]", password, hasher), nil
}
func (hasher DummyHasher) Validate(password string, hash string) error {
	if h, _ := hasher.Hash(password); h == hash {
		return nil
	} else {
		return errors.New("bad password")
	}
}
