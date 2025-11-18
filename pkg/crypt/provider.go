package crypt

import (
	"context"
	"errors"
)

type ProviderOpts struct {
	PrivateKeyHex string
	OwnerDID      string
}

// WithOwnerPrivateKeyHex returns a copy of ProviderOpts with OwnerPrivateKeyHex set.
func (o ProviderOpts) WithOwnerPrivateKeyHex(hex string) ProviderOpts {
	o.PrivateKeyHex = hex
	return o
}

// WithOwnerDID returns a copy of ProviderOpts with OwnerDID set.
func (o ProviderOpts) WithOwnerDID(did string) ProviderOpts {
	o.OwnerDID = did
	return o
}

type Provider interface {
	NewPreDecryptor(ctx context.Context, capsule string, opts ProviderOpts) (*PreDecryptor, error)
}

type DefaultProvider struct{}

func (p *DefaultProvider) NewPreDecryptor(ctx context.Context, capsule string, opts ProviderOpts) (*PreDecryptor, error) {
	if capsule == "" {
		return nil, errors.New("capsule is required")
	}
	if opts.PrivateKeyHex == "" {
		return nil, errors.New("owner private key hex is required")
	}

	return NewPreDecryptor(PreDecryptorOptions{
		PrivateKeyHex: opts.PrivateKeyHex,
		CapsuleHex:    capsule,
	})
}
