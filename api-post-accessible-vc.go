package filesdk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	pre "github.com/pilacorp/nda-reencryption-sdk/pre"
)

// PostAccessibleVCOpt configures PostAccessibleVC call options.
type PostAccessibleVCOpt func(*postAccessibleVCOptions)

// postAccessibleVCOptions holds configuration for PostAccessibleVC call.
type postAccessibleVCOptions struct {
	accessibleSchemaURL string
	ownerPrivateKeyHex  string
	role                string
	permissions         []string
	validFrom           time.Time
}

// getPostAccessibleVCOptions applies functional options and sets defaults.
func getPostAccessibleVCOptions(opts ...PostAccessibleVCOpt) *postAccessibleVCOptions {
	o := &postAccessibleVCOptions{
		// Defaults
		role:        "viewer",
		permissions: []string{"read"},
		validFrom:   time.Now(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// WithAccessibleSchemaURL sets the schema URL for the Accessible VC.
func WithAccessibleSchemaURL(url string) PostAccessibleVCOpt {
	return func(o *postAccessibleVCOptions) {
		o.accessibleSchemaURL = url
	}
}

// WithOwnerPrivateKeyHex sets the owner's private key (hex-encoded),
// used to create the re-capsule and sign the VC.
func WithOwnerPrivateKeyHex(hexKey string) PostAccessibleVCOpt {
	return func(o *postAccessibleVCOptions) {
		o.ownerPrivateKeyHex = hexKey
	}
}

// WithDocumentRole customizes the "role" field in the VC subject.
func WithDocumentRole(role string) PostAccessibleVCOpt {
	return func(o *postAccessibleVCOptions) {
		if role != "" {
			o.role = role
		}
	}
}

// WithPermissions customizes the permissions list for the VC.
func WithPermissions(perms ...string) PostAccessibleVCOpt {
	return func(o *postAccessibleVCOptions) {
		if len(perms) > 0 {
			o.permissions = perms
		}
	}
}

// WithAccessibleValidFrom overrides the ValidFrom timestamp of the VC.
func WithAccessibleValidFrom(t time.Time) PostAccessibleVCOpt {
	return func(o *postAccessibleVCOptions) {
		if !t.IsZero() {
			o.validFrom = t
		}
	}
}

func (c *Client) PostAccessibleVC(
	ctx context.Context,
	ownerDID, viewerDID, cid, capsule string,
	opts ...PostAccessibleVCOpt,
) (string, error) {
	_ = ctx // currently unused, but kept for future-proofing / symmetry

	options := getPostAccessibleVCOptions(opts...)

	if options.ownerPrivateKeyHex == "" {
		return "", errors.New("filesdk: owner private key hex is required (use WithOwnerPrivateKeyHex)")
	}
	if options.accessibleSchemaURL == "" {
		return "", errors.New("filesdk: accessible schema URL is required (use WithAccessibleSchemaURL)")
	}

	// 1. Decode capsule
	capsuleBytes, err := hex.DecodeString(capsule)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to decode capsule: %w", err)
	}

	// 2. Get public key from DID resolver
	publicKey, err := c.resolver.GetPublicKey(viewerDID + "#key-1")
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to get public key: %w", err)
	}

	// 3. Create re-capsule
	reCapsule, err := pre.CreateReCapsule(options.ownerPrivateKeyHex, publicKey, capsuleBytes)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to create re-capsule: %w", err)
	}
	reCapsuleHex := hex.EncodeToString(reCapsule)

	// 4. Build VC payload
	payloadCreateVC := vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		Issuer:  ownerDID,
		Subject: []vc.Subject{
			{
				ID: viewerDID,
				CustomFields: map[string]any{
					"cid":         cid,
					"role":        options.role,
					"permissions": options.permissions,
					"capsule":     reCapsuleHex,
				},
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   options.accessibleSchemaURL,
				Type: "JsonSchema",
			},
		},
		Types: []string{"VerifiableCredential", "DocumentAccessCredential"},
	}

	// Valid from: configured (default: now). No validUntil.
	payloadCreateVC.ValidFrom = options.validFrom

	// 5. Create VC using credential SDK
	vcJWT, err := vc.NewJWTCredential(payloadCreateVC)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to create VC: %w", err)
	}

	if err := vcJWT.AddProof(options.ownerPrivateKeyHex); err != nil {
		return "", fmt.Errorf("filesdk: failed to add proof: %w", err)
	}

	serializedVC, err := vcJWT.Serialize()
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to serialize VC: %w", err)
	}

	vcStr, ok := serializedVC.(string)
	if !ok {
		return "", fmt.Errorf("filesdk: serialized VC is not a string (type %T)", serializedVC)
	}

	return vcStr, nil
}
