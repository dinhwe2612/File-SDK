package filesdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
	pre "github.com/pilacorp/nda-reencryption-sdk/pre"
)

// GetAccessibleVCRequest represents the request of a GetAccessibleVC operation.
type GetAccessibleVCRequest struct {
	OwnerDID            string
	ViewerDID           string
	CID                 string
	Capsule             string
	AccessibleSchemaURL string
	PrivKeyHex          string
}

// PostAccessibleVC creates a new accessible VC for a given CID.
func (c *Client) PostAccessibleVC(
	ctx context.Context,
	request GetAccessibleVCRequest,
) (string, error) {
	// Create re-capsule
	capsuleBytes, err := hex.DecodeString(request.Capsule)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to decode capsule: %w", err)
	}

	// Get public key from DID resolver
	publicKey, err := c.resolver.GetPublicKey(request.ViewerDID + "#key-1")
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to get public key: %w", err)
	}

	// Create re-capsule
	reCapsule, err := pre.CreateReCapsule(request.PrivKeyHex, publicKey, capsuleBytes)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to create re-capsule: %w", err)
	}
	reCapsuleHex := hex.EncodeToString(reCapsule)

	// Create payload for creating VC
	payloadCreateVC := vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		Issuer:  request.OwnerDID,
		Subject: []vc.Subject{
			{
				ID: request.ViewerDID,
				CustomFields: map[string]any{
					"cid":         request.CID,
					"role":        "viewer",
					"permissions": []string{"read"},
					"capsule":     reCapsuleHex,
				},
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   request.AccessibleSchemaURL,
				Type: "JsonSchema",
			},
		},
		Types: []string{"VerifiableCredential", "DocumentAccessCredential"},
	}

	// Set valid_from to current time. VC has no valid_until.
	validFrom := time.Now()
	payloadCreateVC.ValidFrom = validFrom

	// Create VC using credential sdk
	vcJWT, err := vc.NewJWTCredential(payloadCreateVC)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to create VC: %w", err)
	}

	vcJWT.AddProof(request.PrivKeyHex)

	serializedVC, err := vcJWT.Serialize()
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to serialize VC: %w", err)
	}

	return serializedVC.(string), nil
}
