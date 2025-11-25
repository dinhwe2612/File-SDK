package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// global configuration that should be set by the caller.
var (
	accessibleSchemaID string // schema for DocumentAccessCredential
	pilaAuthURL        string // URL of the Pila auth service
)

// SetAccessibleSchemaID sets the schema ID used for owner file credentials.
func SetAccessibleSchemaID(id string) {
	accessibleSchemaID = id
}

// SetPilaAuthURL sets the URL of the Pila auth service.
func SetPilaAuthURL(url string) {
	pilaAuthURL = url
}

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
	ctx context.Context,
	cid string,
	issuerDID string,
	ownerDID string,
	capsule string,
) (string, error) {
	if accessibleSchemaID == "" {
		return "", errors.New("filesdk: accessibleSchemaID is not configured (use SetAccessibleSchemaID)")
	}
	if pilaAuthURL == "" {
		return "", errors.New("filesdk: pilaAuthURL is not configured")
	}

	payloadCreateVC := &CreateCredentialPayload{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Issuer:  issuerDID,
		CredentialSubject: []map[string]any{
			{
				"id":   ownerDID,
				"cid":  cid,
				"role": "owner_file",
				"permissions": []any{
					"*",
				},
				"capsule": capsule,
			},
		},
		CredentialSchema: []map[string]any{
			{
				"id":   accessibleSchemaID,
				"type": "JsonSchema",
			},
		},
		Types: []string{"VerifiableCredential", "DocumentAccessCredential"},
	}

	// Set valid_from to current time. VC has no valid_until.
	validFrom := time.Now()
	payloadCreateVC.ValidFrom = &validFrom

	// TODO: authentication by VP JWT.
	return CreateCredentialNoAuth(ctx, "", payloadCreateVC)
}

// CreateCredentialNoAuth calls the Pila auth service to create a credential without VP auth.
func CreateCredentialNoAuth(
	ctx context.Context,
	vpJWT string,
	credential *CreateCredentialPayload,
) (string, error) {
	if pilaAuthURL == "" {
		return "", errors.New("filesdk: pilaAuthURL is not configured")
	}

	payload, err := json.Marshal(credential)
	if err != nil {
		return "", fmt.Errorf("filesdk: failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/api/v2/credentials/no-auth", pilaAuthURL),
		bytes.NewReader(payload),
	)
	if err != nil {
		slog.ErrorContext(ctx, "create credential no auth -> failed to create request",
			"vpJWT", vpJWT, "error", err)
		return "", fmt.Errorf("filesdk: failed to create request: %w", err)
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	if vpJWT != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", vpJWT))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "create credential no auth -> failed to execute request",
			"vpJWT", vpJWT, "error", err)
		return "", fmt.Errorf("filesdk: failed to execute request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		slog.ErrorContext(ctx, "create credential no auth -> failed to create credential",
			"vpJWT", vpJWT, "status", res.StatusCode, "body", string(body))
		return "", fmt.Errorf("filesdk: auth service returned status %d: %s", res.StatusCode, string(body))
	}

	var result struct {
		Data string `json:"data"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		slog.ErrorContext(ctx, "create credential no auth -> failed to decode response",
			"vpJWT", vpJWT, "error", err)
		return "", fmt.Errorf("filesdk: failed to decode response: %w", err)
	}

	return result.Data, nil
}
