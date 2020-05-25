package events

import (
	"github.com/universe-10th/identity/credentials"
	"sync"
)

// A login success/failure callback.
type LoginCallback func(identifier interface{}, password, realm string, credential credentials.Credential, err error)

// Login events, either for success or failure,
// involve a login attempt to be audited. Callbacks
// can be registered to attend this event.
type LoginEvent struct {
	counter   uint
	callbacks map[uint]LoginCallback
	mutex     sync.Mutex
}

// Registers a non-null login callback.
func (event *LoginEvent) Register(callback LoginCallback) func() {
	const MaxInt = uint(^uint(0) >> 1)
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
func (event *LoginEvent) trigger(callback LoginCallback, identifier interface{}, password, realm string, credential credentials.Credential, err error) {
	defer func() { recover() }()
	callback(identifier, password, realm, credential, err)
}

// Triggers all the callbacks. Hopefully, few callbacks will be triggered.
func (event *LoginEvent) Trigger(identifier interface{}, password, realm string, credential credentials.Credential, err error) {
	for _, callback := range event.callbacks {
		event.trigger(callback, identifier, password, realm, credential, err)
	}
}
