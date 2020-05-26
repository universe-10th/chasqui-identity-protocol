package events

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/identity/credentials"
	"sync"
)

// A password-change callback. It is recorded whether the
// password was successfully changed or not.
type PasswordChangeCallback func(*chasqui.Server, *chasqui.Attendant, credentials.Credential, error)

// Password-change events involve a password change issued
// by the same user to be audited. Callbacks can be
// registered to attend this event, but the involved
// password will NOT be logged.
type PasswordChangeEvent struct {
	counter   uint
	callbacks map[uint]PasswordChangeCallback
	mutex     sync.Mutex
}

// Registers a non-null password-change callback.
func (event *PasswordChangeEvent) Register(callback PasswordChangeCallback) func() {
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
func (event *PasswordChangeEvent) trigger(callback PasswordChangeCallback, server *chasqui.Server, attendant *chasqui.Attendant, credential credentials.Credential, err error) {
	defer func() { recover() }()
	callback(server, attendant, credential, err)
}

// Triggers all the callbacks. Hopefully, few callbacks will be triggered.
func (event *PasswordChangeEvent) Trigger(server *chasqui.Server, attendant *chasqui.Attendant, credential credentials.Credential, err error) {
	for _, callback := range event.callbacks {
		event.trigger(callback, server, attendant, credential, err)
	}
}
