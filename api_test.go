package filesdk_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	filesdk "github.com/dinhwe2612/file-sdk"

	"github.com/pilacorp/nda-auth-sdk/provider"
	"github.com/pilacorp/nda-reencryption-sdk/pre"
	"github.com/pilacorp/nda-reencryption-sdk/utils"
)

// mockResolver is a simple resolver for testing that returns a fixed public key
type mockResolver struct {
	publicKeyHex string
}

func (m *mockResolver) GetPublicKey(verificationMethodURL string) (string, error) {
	return m.publicKeyHex, nil
}

// mockAuth is a simple mock auth client for testing
type mockAuth struct {
	requester string // The requester DID to return from VerifyToken
}

func (m *mockAuth) VerifyToken(ctx context.Context, token string) ([]map[string]any, string, []string, error) {
	// Return mock values for testing
	// If requester is not set, default to "test-owner-did" to match most tests
	requester := m.requester
	if requester == "" {
		requester = "test-owner-did"
	}
	return []map[string]any{}, requester, []string{"test-vc-jwt"}, nil
}

func (m *mockAuth) VerifyTokenWithStructs(ctx context.Context, token string, targets []any) error {
	// Mock implementation - just return nil for testing
	return nil
}

func (m *mockAuth) CreateToken(ctx context.Context, vcJWTs []string, applicationDID string, opts ...provider.SignOption) (string, error) {
	// Return a mock token
	return "mock-vp-token", nil
}

func generatePREKeys(t *testing.T) (privHex string, pubHex string) {
	priv, pub, err := utils.GenerateKeys()
	if err != nil {
		t.Fatalf("Failed to generate PRE keys: %v", err)
	}
	return utils.PrivateKeyToHexString(priv), utils.PublicKeyToCompressedKey(pub)
}

// TestPutObjectPublic tests uploading a public object (no encryption)
func TestPutObjectPublic(t *testing.T) {
	ownerDID := "test-owner-did"
	issuerDID := "test-issuer-did"

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Parse multipart form
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatalf("Failed to parse multipart form: %v", err)
		}

		// Check form fields reflect owner + issuer semantics
		if r.FormValue("owner_did") != ownerDID {
			t.Errorf("Expected owner_did '%s', got '%s'", ownerDID, r.FormValue("owner_did"))
		}
		// Note: issuer_did will be the value passed to WithIssuerDID, which is ownerDID in this test
		if r.FormValue("issuer_did") != ownerDID {
			t.Errorf("Expected issuer_did '%s', got '%s'", ownerDID, r.FormValue("issuer_did"))
		}
		if r.FormValue("access_level") != "public" {
			t.Errorf("Expected access_level 'public', got '%s'", r.FormValue("access_level"))
		}

		// Return JSON response
		response := map[string]interface{}{
			"cid":          "test-cid-123",
			"owner_did":    ownerDID,
			"created_at":   time.Now().Format(time.RFC3339),
			"file_name":    "test-key",
			"file_type":    "text/plain",
			"access_level": "public",
			"issuer_did":   issuerDID,
			"size":         42,
			"capsule":      "",
			"owner_vc_jwt": "",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create a mock resolver for public uploads (not actually used for public)
	mockResolver := &mockResolver{publicKeyHex: ""}
	// Use ownerDID as requester since we're passing ownerDID as issuerDID
	mockAuth := &mockAuth{requester: ownerDID}

	// Create client
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: mockResolver,
		Auth:     mockAuth,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a public object.")
	reader := bytes.NewReader(testData)

	// Upload public object - bucketName is owner DID
	// PutObject requires Authorization header
	// Note: Using ownerDID as issuerDID to match what the test expects
	headers := http.Header{}
	headers.Set("Authorization", "test-owner-jwt")
	info, err := client.PutObject(context.Background(), ownerDID, "test-key", reader, int64(len(testData)),
		filesdk.WithAccessType(filesdk.AccessTypePublic),
		filesdk.WithContentType("text/plain"),
		filesdk.WithIssuerDID(ownerDID), // Using ownerDID as issuerDID for this test
		filesdk.WithHeaders(headers),
	)
	if err != nil {
		t.Fatalf("Failed to put object: %v", err)
	}

	if info.CID != "test-cid-123" {
		t.Errorf("Expected CID 'test-cid-123', got '%s'", info.CID)
	}
}

// TestEncryptDecryptRoundTrip tests encryption and decryption round trip
func TestEncryptDecryptRoundTrip(t *testing.T) {
	privHex, pubHex := generatePREKeys(t)

	originalData := []byte("This is test data that will be encrypted and decrypted.")
	input := bytes.NewReader(originalData)

	const chunkSize = 64 * 1024
	encryptor, capsule, err := pre.NewEncryptor(pubHex, chunkSize)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	var cipherBuf bytes.Buffer
	if err := encryptor.EncryptStream(context.Background(), input, &cipherBuf); err != nil {
		t.Fatalf("Failed to encrypt stream: %v", err)
	}

	cipherData := cipherBuf.Bytes()
	if bytes.Equal(cipherData, originalData) {
		t.Error("Data was not encrypted")
	}
	if len(cipherData) <= len(originalData) {
		t.Error("Encrypted data should be longer than original (due to chunk framing)")
	}

	decryptor, err := pre.NewDecryptorByOwner(privHex, capsule)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	var plainBuf bytes.Buffer
	if err := decryptor.DecryptStream(context.Background(), bytes.NewReader(cipherData), &plainBuf); err != nil {
		t.Fatalf("Failed to decrypt stream: %v", err)
	}

	if !bytes.Equal(plainBuf.Bytes(), originalData) {
		t.Errorf("Decrypted data mismatch. Expected %q, got %q", originalData, plainBuf.Bytes())
	}
}

// TestPutObjectPrivateMissingVerification ensures private upload validates resolver config
func TestPutObjectPrivateMissingVerification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create client with a resolver (resolver is always required now)
	mockResolver := &mockResolver{publicKeyHex: ""}
	// Use "test-owner-did" as requester since we're passing it as issuerDID
	mockAuth := &mockAuth{requester: "test-owner-did"}
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: mockResolver,
		Auth:     mockAuth,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	testData := []byte("test data")
	reader := bytes.NewReader(testData)

	// Try to upload private object - should work with resolver, but might fail on encryption
	// PutObject requires Authorization header
	headers := http.Header{}
	headers.Set("Authorization", "test-owner-jwt")
	_, err = client.PutObject(context.Background(), "test-owner-did", "test-key", reader, int64(len(testData)),
		filesdk.WithAccessType(filesdk.AccessTypePrivate),
		filesdk.WithIssuerDID("test-owner-did"),
		filesdk.WithHeaders(headers),
	)

	// With resolver required, the error will be about getting the public key, not about missing resolver
	if err == nil {
		t.Error("Expected error when uploading private object with invalid resolver")
	}
	if !strings.Contains(err.Error(), "failed to get public key") &&
		!strings.Contains(err.Error(), "resolver") &&
		!strings.Contains(err.Error(), "invalid public key") {
		t.Errorf("Expected error about resolver, public key, or invalid public key, got: %v", err)
	}
}
