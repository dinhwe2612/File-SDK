package crypt

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pilacorp/nda-reencryption-sdk/pre"
)

// ProviderOpt configures provider options.
type ProviderOpt func(*providerOptions)

// providerOptions holds configuration for provider operations.
type providerOptions struct {
	privKeyHex    string
	customOptions map[string]any
}

// WithPrivateKeyHex sets the private key in hex format.
func WithPrivKeyHex(privKeyHex string) ProviderOpt {
	return func(o *providerOptions) {
		o.privKeyHex = privKeyHex
	}
}

// WithCustomProvider sets custom provider data.
func WithCustomProvider(customOptions map[string]any) ProviderOpt {
	return func(o *providerOptions) {
		o.customOptions = customOptions
	}
}

// getProviderOptions returns the providerOptions with defaults applied.
func getProviderOptions(opts ...ProviderOpt) *providerOptions {
	options := &providerOptions{
		privKeyHex:    "",
		customOptions: make(map[string]any),
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

type Provider interface {
	NewPreDecryptor(ctx context.Context, capsule string, opts ...ProviderOpt) (*pre.Decryptor, error)
}

type DefaultProvider struct{}

func (p *DefaultProvider) NewPreDecryptor(ctx context.Context, capsule string, opts ...ProviderOpt) (*pre.Decryptor, error) {
	if capsule == "" {
		return nil, errors.New("capsule is required")
	}

	options := getProviderOptions(opts...)
	if options.privKeyHex == "" {
		return nil, errors.New("owner private key hex is required")
	}

	capsuleBytes, err := hex.DecodeString(capsule)
	if err != nil {
		return nil, fmt.Errorf("decode capsule: %w", err)
	}

	if len(capsuleBytes) == 185 {
		return pre.NewDecryptorByOwner(options.privKeyHex, capsuleBytes)
	} else {
		return pre.NewDecryptor(options.privKeyHex, capsuleBytes)
	}
}
