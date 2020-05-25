package events

// Provides the 4 events via methods:
// - Login attempt.
// - Logout.
// - Password change.
type WithAuthEvents struct {
	onLogin          *LoginEvent
	onLogout         *LogoutEvent
	onPasswordChange *PasswordChangeEvent
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

// Creates an instance of WithAuthEvents
// which is prepopulated with new instances
// of the events.
func NewWithAuthEvents() WithAuthEvents {
	return WithAuthEvents{
		onLogin:          &LoginEvent{counter: 0, callbacks: map[uint]LoginCallback{}},
		onLogout:         &LogoutEvent{counter: 0, callbacks: map[uint]LogoutCallback{}},
		onPasswordChange: &PasswordChangeEvent{counter: 0, callbacks: map[uint]PasswordChangeCallback{}},
	}
}
