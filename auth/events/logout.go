package events

import (
	"github.com/universe-10th/identity/credentials"
	"sync"
)

// A logout success callback. Logout only means
// dropping a context value in an attendant.
type LogoutCallback func(credential credentials.Credential)

// Logout events involve a logout command to be
// audited. Callbacks can be registered to attend
// this event.
type LogoutEvent struct {
	counter   uint
	callbacks map[uint]LogoutCallback
	mutex     sync.Mutex
}

// Registers a non-null logout callback.
func (event *LogoutEvent) Register(callback LogoutCallback) func() {
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
func (event *LogoutEvent) trigger(callback LogoutCallback, credential credentials.Credential) {
	defer func() { recover() }()
	callback(credential)
}

// Triggers all the callbacks. Hopefully, few callbacks will be triggered.
func (event *LogoutEvent) Trigger(credential credentials.Credential) {
	for _, callback := range event.callbacks {
		event.trigger(callback, credential)
	}
}
