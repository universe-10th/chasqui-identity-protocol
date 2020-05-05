package events

import (
	"github.com/universe-10th/identity/credentials"
	"sync"
)

// A password-recover callback. It is recorded whether the
// password was successfully prepared, recovered, or cancelled,
// or not. This action is performed by a non-logged user. It
// will take the token (to be sent, say, by e-mail) and the
// target credential. It will also take the stage of recovery:
// "prepare", "confirm", or "cancel".
type PasswordRecoverCallback func(target credentials.Credential, stage, token string, err error)

// Password-recover events involve a password recover
// issued by a non-logged user. Callbacks can be
// registered to attend this event, but the involved
// password will NOT be logged (the involved token will).
type PasswordRecoverEvent struct {
	counter   uint
	callbacks map[uint]PasswordRecoverCallback
	mutex     sync.Mutex
}

// Registers a non-null password-recover callback.
func (event *PasswordRecoverEvent) Register(callback PasswordRecoverCallback) func() {
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
func (event *PasswordRecoverEvent) trigger(callback PasswordRecoverCallback, target credentials.Credential, stage, token string, err error) {
	defer func() { recover() }()
	callback(target, stage, token, err)
}

// Triggers all the callbacks. Hopefully, few callbacks will be triggered.
func (event *PasswordRecoverEvent) Trigger(target credentials.Credential, stage, token string, err error) {
	for _, callback := range event.callbacks {
		event.trigger(callback, target, stage, token, err)
	}
}
