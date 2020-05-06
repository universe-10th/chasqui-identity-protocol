package events

// Provides the 4 events via methods:
// - Login attempt.
// - Logout.
// - Password change.
// - Password [un]set by admin.
type WithAuthEvents struct {
	onLogin          *LoginEvent
	onLogout         *LogoutEvent
	onPasswordChange *PasswordChangeEvent
	onPasswordForce  *PasswordForceEvent
}

// Returns a reference to the login event.
func (withAuthEvents *WithAuthEvents) OnLogin() *LoginEvent {
	return withAuthEvents.onLogin
}

// Returns a reference to the logout event.
func (withAuthEvents *WithAuthEvents) OnLogout() *LogoutEvent {
	return withAuthEvents.onLogout
}

// Returns a reference to the password change event.
func (withAuthEvents *WithAuthEvents) OnPasswordChange() *PasswordChangeEvent {
	return withAuthEvents.onPasswordChange
}

// Returns a reference to the password force event.
func (withAuthEvents *WithAuthEvents) OnPasswordForce() *PasswordForceEvent {
	return withAuthEvents.onPasswordForce
}

// Creates an instance of WithAuthEvents
// which is prepopulated with new instances
// of the events.
func NewWithAuthEvents() WithAuthEvents {
	return WithAuthEvents{
		onLogin:          &LoginEvent{counter: 0, callbacks: map[uint]LoginCallback{}},
		onLogout:         &LogoutEvent{counter: 0, callbacks: map[uint]LogoutCallback{}},
		onPasswordChange: &PasswordChangeEvent{counter: 0, callbacks: map[uint]PasswordChangeCallback{}},
		onPasswordForce:  &PasswordForceEvent{counter: 0, callbacks: map[uint]PasswordForceCallback{}},
	}
}
