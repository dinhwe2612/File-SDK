package credential

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// CapsuleFromJWT extracts vc.credentialSubject.capsule from a JWT token.
// Supports both direct VC claims and Verifiable Presentation (VP) formats
// where the VC is nested inside vp.verifiableCredential entries.
func CapsuleFromJWT(token string) (string, error) {
	claims, err := parseJWT(token)
	if err != nil {
		return "", fmt.Errorf("parse jwt: %w", err)
	}

	// Try extracting from VP first (most common for presentations)
	if claims.VP != nil {
		if capsule, err := capsuleFromVP(claims.VP); err == nil {
			return capsule, nil
		}
	}

	// Fallback to direct VC claims at the top level
	if claims.VC != nil {
		return capsuleFromVC(claims.VC)
	}

	return "", errors.New("no verifiable credential capsule found in JWT")
}

// capsuleFromVP extracts the capsule from a Verifiable Presentation (VP)
func capsuleFromVP(vp *vpClaims) (string, error) {
	if vp == nil || len(vp.VerifiableCredential) == 0 {
		return "", errors.New("no verifiableCredential entries in VP")
	}

	for _, entry := range vp.VerifiableCredential {
		// First try to interpret the entry as a JWT string
		var vcJWT string
		if err := json.Unmarshal(entry, &vcJWT); err == nil {
			claims, err := parseJWT(vcJWT)
			if err != nil {
				continue
			}
			if claims.VC != nil {
				if capsule, err := capsuleFromVC(claims.VC); err == nil {
					return capsule, nil
				}
			}
			continue
		}

		// Otherwise, try to parse as an embedded VC object
		var vc vcClaims
		if err := json.Unmarshal(entry, &vc); err == nil {
			if capsule, err := capsuleFromVC(&vc); err == nil {
				return capsule, nil
			}
		}
	}

	return "", errors.New("capsule not found in verifiableCredential entries")
}

// capsuleFromVC extracts the capsule from a VC credentialSubject
func capsuleFromVC(vc *vcClaims) (string, error) {
	if vc == nil {
		return "", errors.New("verifiable credential is nil")
	}

	if vc.CredentialSubject == nil {
		return "", errors.New("no credentialSubject in verifiableCredential")
	}

	capsuleValue, ok := vc.CredentialSubject["capsule"]
	if !ok {
		return "", errors.New("capsule not found in credentialSubject")
	}

	capsule, ok := capsuleValue.(string)
	if !ok {
		return "", fmt.Errorf("capsule is not a string, got type: %T", capsuleValue)
	}

	return capsule, nil
}

type jwtClaims struct {
	VC *vcClaims `json:"vc,omitempty"`
	VP *vpClaims `json:"vp,omitempty"`
}

type vpClaims struct {
	VerifiableCredential []json.RawMessage `json:"verifiableCredential"`
}

type vcClaims struct {
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
}

func parseJWT(token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	return &claims, nil
}
