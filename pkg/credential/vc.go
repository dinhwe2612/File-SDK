package credential

import (
	"context"
	"fmt"
	"time"

	"github.com/pilacorp/go-credential-sdk/credential/vc"
)

type CreateCredentialPayload struct {
	Context           []string         `json:"context"`
	CredentialSchema  []map[string]any `json:"credentialSchema"`
	CredentialSubject []map[string]any `json:"credentialSubject"`
	Issuer            string           `json:"issuer"`
	Types             []string         `json:"types"`
	ValidFrom         *time.Time       `json:"validFrom,omitempty"`
	ValidUntil        *time.Time       `json:"validUntil,omitempty"`
}

// CreateOwnerFileCredential creates an accessible credential using the Pila auth service.
func CreateOwnerFileCredential(
	_ context.Context,
	cid string,
	issuerDID string,
	ownerDID string,
	capsule string,
	schemaURL string,
	privKeyHex string,
) (string, error) {
	payloadCreateVC := vc.CredentialContents{
		Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
		Issuer:  issuerDID,
		Subject: []vc.Subject{
			{
				ID: ownerDID,
				CustomFields: map[string]any{
					"cid":         cid,
					"role":        "owner_file",
					"permissions": []string{"*"},
					"capsule":     capsule,
				},
			},
		},
		Schemas: []vc.Schema{
			{
				ID:   schemaURL,
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

	err = vcJWT.AddProof(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to add proof to VC: %w", err)
	}

	serializedVC, err := vcJWT.Serialize()
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to serialize VC: %w", err)
	}

	return serializedVC.(string), nil
}
