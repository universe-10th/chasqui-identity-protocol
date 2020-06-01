package auth

import (
	"github.com/universe-10th/chasqui-identity-protocols/auth/types"
	protocols "github.com/universe-10th/chasqui-protocols"
)

// This type represents an option to the NewAuthProtocol()
// builder. Several options set different arguments of the
// being-built auth protocol instance.
type AuthOption func(protocol *AuthProtocol)

// This option sets the domain, of a being-built
// auth protocol instance, to a new SingleLocking
// domain.
func WithSingleLockingDomain(protocol *AuthProtocol) {
	protocol.domain = types.NewDomain(types.SingleLocking, nil)
}

// This option sets the domain, of a being-built
// auth protocol instance, to a new SingleGhosting
// domain.
func WithSingleGhostingDomain(protocol *AuthProtocol) {
	protocol.domain = types.NewDomain(types.SingleGhosting, nil)
}

// This option sets the domain, of a being-built
// auth protocol instance, to a new Multiple domain.
func WithMultipleDomain(protocol *AuthProtocol) {
	protocol.domain = types.NewDomain(types.Multiple, nil)
}

// This option-maker returns an option that sets
// the domain, of a being-built auth protocol instance,
// to a new Custom domain with the given criterion.
func WithCustomDomain(criterion types.DomainCustomCriterion) AuthOption {
	return func(protocol *AuthProtocol) {
		protocol.domain = types.NewDomain(types.Custom, criterion)
	}
}

// This option-maker returns an option that sets
// the handler of the case when a not-logged attendant
// wants to execute an action that required login.
func WithDefaultNotLoggedIn(notLoggedIn protocols.MessageHandler) AuthOption {
	return func(protocol *AuthProtocol) {
		protocol.notLoggedInHandler = notLoggedIn
	}
}

// This option-maker returns an option that sets
// the handler of the case when an attendant wants
// to execute an action that required more permissions.
func WithDefaultPermissionDenied(permissionDenied protocols.MessageHandler) AuthOption {
	return func(protocol *AuthProtocol) {
		protocol.permissionDeniedHandler = permissionDenied
	}
}

// This option-maker returns an option that sets
// the prefix to use in the auth protocol. If this
// option is not used, the prefix will be "auth".
func WithPrefix(prefix string) AuthOption {
	return func(protocol *AuthProtocol) {
		protocol.prefix = prefix
	}
}
