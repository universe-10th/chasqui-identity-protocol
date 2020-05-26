package events

import (
	"github.com/universe-10th/chasqui"
	"github.com/universe-10th/identity/credentials"
	"sync"
)

// The stage to catch the logout event: before logging
// out (for cleanup and logic termination purposes), or
// after the logout was done (for reporting purposes).
type LogoutStage uint

const (
	Before LogoutStage = iota
	After
)

// A logout success callback. Logout only means
// dropping a context value in an attendant.
type LogoutCallback func(*chasqui.Server, *chasqui.Attendant, credentials.Credential, LogoutStage)

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
func (event *LogoutEvent) trigger(callback LogoutCallback, server *chasqui.Server, attendant *chasqui.Attendant, credential credentials.Credential, stage LogoutStage) {
	defer func() { recover() }()
	callback(server, attendant, credential, stage)
}

// Triggers all the callbacks. Hopefully, few callbacks will be triggered.
func (event *LogoutEvent) Trigger(server *chasqui.Server, attendant *chasqui.Attendant, credential credentials.Credential, stage LogoutStage) {
	for _, callback := range event.callbacks {
		event.trigger(callback, server, attendant, credential, stage)
	}
}
