package identity

import protocols "github.com/universe-10th/chasqui-protocols"

// Fallback options configure the internal values to be
// used as callbacks when either the user is not logged
// in or the requirements are not satisfied.
type FallbackOption func(protocols.MessageHandler, protocols.MessageHandler) (protocols.MessageHandler, protocols.MessageHandler)

// This option sets a custom notLoggedIn callback.
func WithNotLoggedIn(handler protocols.MessageHandler) FallbackOption {
	return func(_, permissionDenied protocols.MessageHandler) (protocols.MessageHandler, protocols.MessageHandler) {
		return handler, permissionDenied
	}
}

// This option sets a custom permissionDenied callback.
func WithPermissionDenied(handler protocols.MessageHandler) FallbackOption {
	return func(notLoggedIn, _ protocols.MessageHandler) (protocols.MessageHandler, protocols.MessageHandler) {
		return notLoggedIn, handler
	}
}
