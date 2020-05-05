package events

import (
	"github.com/universe-10th/identity/credentials"
	"sync"
)

// A password-force callback. It is recorded whether the
// password was successfully set/unset or not. This action
// is performed by an administrator to a regular user.
type PasswordForceCallback func(forcing, forced credentials.Credential, passwordSet bool, err error)

// Password-force events involve a password set issued
// by an administrator to a regular user (or other
// administrator) to be audited. Callbacks can be
// registered to attend this event, but the involved
// password will NOT be logged.
type PasswordForceEvent struct {
	counter   uint
	callbacks map[uint]PasswordForceCallback
	mutex     sync.Mutex
}

// Registers a non-null password-force callback.
func (event *PasswordForceEvent) Register(callback PasswordForceCallback) func() {
	const MaxInt = ^uint(0) >> 1
	event.mutex.Lock()
	defer event.mutex.Unlock()

	if callback == nil || uint(len(event.callbacks)) >= MaxInt {
		return nil
	}

	current := event.counter
	event.callbacks[current] = callback

	for {
		if event.counter == MaxInt {
			event.counter = 0
		} else if _, ok := event.callbacks[event.counter]; ok {
			event.counter++
		} else {
			break
		}
	}

	return func() {
		delete(event.callbacks, current)
	}
}

// Wraps and triggers a callback, by calling it and diaper-catching
// any panic.
func (event *PasswordForceEvent) trigger(callback PasswordForceCallback, forcing, forced credentials.Credential, passwordSet bool, err error) {
	defer func() { recover() }()
	callback(forcing, forced, passwordSet, err)
}

// Triggers all the callbacks. Hopefully, few callbacks will be triggered.
func (event *PasswordForceEvent) Trigger(forcing, forced credentials.Credential, passwordSet bool, err error) {
	for _, callback := range event.callbacks {
		event.trigger(callback, forcing, forced, passwordSet, err)
	}
}
