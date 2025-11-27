package filesdk

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/credential"
	"github.com/pilacorp/go-credential-sdk/credential/vc"
	pre "github.com/pilacorp/nda-reencryption-sdk/pre"
)

// PostAccessibleVCOpt configures PostAccessibleVC call options.
type PostAccessibleVCOpt func(*postAccessibleVCOptions)

// postAccessibleVCOptions holds configuration for PostAccessibleVC call.
type postAccessibleVCOptions struct {
	role            string
	permissions     []string
	validFrom       time.Time
	ownerPrivKeyHex string
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

// WithOwnerPrivKeyHex sets the owner Priv key hex.
func WithOwnerPrivKeyHex(privKeyHex string) PostAccessibleVCOpt {
	return func(o *postAccessibleVCOptions) {
		if privKeyHex != "" {
			o.ownerPrivKeyHex = privKeyHex
		}
	}
}

type PostAccessibleVCInput struct {
	OwnerDID  *string
	ViewerDID *string
	CID       *string
	VCOwner   *string
}

type PostAccessibleVCOutput struct {
	VCJWT *string
}

func (c *Client) PostAccessibleVC(
	ctx context.Context,
	input *PostAccessibleVCInput,
	opts ...PostAccessibleVCOpt,
) (*PostAccessibleVCOutput, error) {
	options := getPostAccessibleVCOptions(opts...)

	// Get owner Priv key hex
	ownerPrivKeyHex := ""
	if options.ownerPrivKeyHex != "" {
		ownerPrivKeyHex = options.ownerPrivKeyHex
	} else if c.ownerPrivKeyHex != nil {
		ownerPrivKeyHex = *c.ownerPrivKeyHex
	}
	if ownerPrivKeyHex == "" {
		return nil, errors.New("filesdk: owner Priv key hex is not configured")
	}

	// Get Owner DID
	if input.OwnerDID == nil || *input.OwnerDID == "" {
		return nil, errors.New("filesdk: owner DID is required")
	}

	// Get Viewer DID
	if input.ViewerDID == nil || *input.ViewerDID == "" {
		return nil, errors.New("filesdk: viewer DID is required")
	}

	// Get CID
	if input.CID == nil || *input.CID == "" {
		return nil, errors.New("filesdk: CID is required")
	}

	// Get accessible schema URL
	if c.accessibleSchemaURL == nil || *c.accessibleSchemaURL == "" {
		return nil, errors.New("filesdk: accessible schema URL is not configured")
	}

	// Get capsule from JWT
	capsuleHex, err := credential.CapsuleFromJWT(*input.VCOwner)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to get capsule from JWT: %w", err)
	}

	capsuleBytes, err := hex.DecodeString(capsuleHex)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to decode capsule: %w", err)
	}

	// Get public key from DID resolver
	publicKey, err := c.resolver.GetPublicKey(*input.ViewerDID + "#key-1")
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to get public key: %w", err)
	}

	// Create re-capsule
	reCapsule, err := pre.CreateReCapsule(ownerPrivKeyHex, publicKey, capsuleBytes)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create re-capsule: %w", err)
	}
	reCapsuleHex := hex.EncodeToString(reCapsule)

	// Build VC payload
	role := "viewer"
	if options.role != "" {
		role = options.role
	}

	permissions := []string{"read"}
	if len(options.permissions) > 0 {
		permissions = options.permissions
	}

	validFrom := time.Now()
	if !options.validFrom.IsZero() {
		validFrom = options.validFrom
	}

	payloadCreateVC := vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		Issuer:  *input.OwnerDID,
		Subject: []vc.Subject{
			{
				ID: *input.ViewerDID,
				CustomFields: map[string]any{
					"cid":         *input.CID,
					"role":        role,
					"permissions": permissions,
					"capsule":     reCapsuleHex,
				},
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   *c.accessibleSchemaURL,
				Type: "JsonSchema",
			},
		},
		Types: []string{"VerifiableCredential", "DocumentAccessCredential"},
	}

	// Valid from: configured (default: now). No validUntil.
	payloadCreateVC.ValidFrom = validFrom

	// Create VC using credential SDK
	vcJWT, err := vc.NewJWTCredential(payloadCreateVC)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create VC: %w", err)
	}

	// Add proof to VC
	if err := vcJWT.AddProof(ownerPrivKeyHex); err != nil {
		return nil, fmt.Errorf("filesdk: failed to add proof: %w", err)
	}

	// Serialize VC
	serializedVC, err := vcJWT.Serialize()
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to serialize VC: %w", err)
	}

	// Convert serialized VC to string
	vcStr, ok := serializedVC.(string)
	if !ok {
		return nil, fmt.Errorf("filesdk: serialized VC is not a string (type %T)", serializedVC)
	}

	return &PostAccessibleVCOutput{
		VCJWT: &vcStr,
	}, nil
}
