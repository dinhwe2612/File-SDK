package crypt

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/dinhwe2612/file-sdk/pkg/resolver"

	pre "github.com/pilacorp/nda-reencryption-sdk/pre"
)

const defaultChunkSize = 1 << 20

// preEncryptor wraps a PRE Encryptor plus its capsule.
type PreEncryptor struct {
	enc        *pre.Encryptor
	capsuleHex string
}

// preDecryptor wraps a PRE Decryptor.
type PreDecryptor struct {
	dec *pre.Decryptor
}

// PreEncryptorOptions are the options for creating a PRE Encryptor.
type PreEncryptorOptions struct {
	Resolver  resolver.Resolver
	ChunkSize int
}

// PreDecryptorOptions are the options for creating a PRE Decryptor.
type PreDecryptorOptions struct {
	PrivateKeyHex string
	CapsuleHex    string
}

// NewPreEncryptor builds a PRE Encryptor by resolving the public key from OwnerDID using the resolver.
func NewPreEncryptor(opts PreEncryptorOptions) (*PreEncryptor, error) {
	// Default chunk size if zero or negative
	chunkSize := opts.ChunkSize
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}

	// Validate resolver
	if opts.Resolver == nil {
		return nil, errors.New("resolver is required")
	}

	// Get public key from resolver
	publicKeyHex, err := opts.Resolver.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key from resolver: %w", err)
	}

	enc, capsule, err := pre.NewEncryptor(publicKeyHex, uint32(chunkSize))
	if err != nil {
		return nil, fmt.Errorf("create PRE encryptor: %w", err)
	}

	return &PreEncryptor{
		enc:        enc,
		capsuleHex: hex.EncodeToString(capsule),
	}, nil
}

// NewPreDecryptor builds a PRE Decryptor bound to a specific owner private key and capsule.
func NewPreDecryptor(opts PreDecryptorOptions) (*PreDecryptor, error) {
	if opts.PrivateKeyHex == "" {
		return nil, errors.New("owner private key hex is required")
	}
	if opts.CapsuleHex == "" {
		return nil, errors.New("capsule hex is required")
	}

	capsuleBytes, err := hex.DecodeString(opts.CapsuleHex)
	if err != nil {
		return nil, fmt.Errorf("decode capsule: %w", err)
	}

	var dec *pre.Decryptor
	// For owner decryption we expect the original capsule (185 bytes),
	// so we must use NewDecryptorByOwner, not the re-encryption decryptor.
	if len(capsuleBytes) == 185 {
		dec, err = pre.NewDecryptorByOwner(opts.PrivateKeyHex, capsuleBytes)
		if err != nil {
			return nil, fmt.Errorf("create PRE decryptor: %w", err)
		}
	} else {
		dec, err = pre.NewDecryptor(opts.PrivateKeyHex, capsuleBytes)
		if err != nil {
			return nil, fmt.Errorf("create PRE decryptor: %w", err)
		}
	}

	return &PreDecryptor{dec: dec}, nil
}

// Encrypt transforms the plaintext reader into an encrypted stream and returns
// the new reader and capsule (hex-encoded).
func (e *PreEncryptor) Encrypt(ctx context.Context, plaintext io.Reader) (io.Reader, string, error) {
	if plaintext == nil {
		return nil, "", errors.New("plaintext reader is required")
	}

	pipeReader, pipeWriter := io.Pipe()

	go func() {
		defer pipeWriter.Close()
		if err := e.enc.EncryptStream(ctx, plaintext, pipeWriter); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.ErrClosedPipe) {
			pipeWriter.CloseWithError(err)
		}
	}()

	return pipeReader, e.capsuleHex, nil
}

// Decrypt transforms the encrypted reader into plaintext.
func (d *PreDecryptor) Decrypt(ctx context.Context, ciphertext io.Reader) (io.ReadCloser, error) {
	if ciphertext == nil {
		return nil, errors.New("ciphertext reader is required")
	}

	pipeReader, pipeWriter := io.Pipe()
	var closer io.Closer
	if c, ok := ciphertext.(io.Closer); ok {
		closer = c
	}

	go func() {
		if closer != nil {
			defer closer.Close()
		}

		if err := d.dec.DecryptStream(ctx, ciphertext, pipeWriter); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.ErrClosedPipe) {
			pipeWriter.CloseWithError(err)
			return
		}

		pipeWriter.Close()
	}()

	return pipeReader, nil
}
