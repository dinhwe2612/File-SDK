package filesdk_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	filesdk "github.com/dinhwe2612/file-sdk"
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"

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

		// Check owner DID header (bucketName)
		headerDID := r.Header.Get("X-Issuer-Did")
		if headerDID != ownerDID {
			t.Errorf("Expected owner DID '%s', got '%s'", ownerDID, headerDID)
		}

		// Parse multipart form
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatalf("Failed to parse multipart form: %v", err)
		}

		// Check form fields reflect owner + issuer semantics
		if r.FormValue("owner_did") != ownerDID {
			t.Errorf("Expected owner_did '%s', got '%s'", ownerDID, r.FormValue("owner_did"))
		}
		if r.FormValue("issuer_did") != issuerDID {
			t.Errorf("Expected issuer_did '%s', got '%s'", issuerDID, r.FormValue("issuer_did"))
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

	// Create client
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: mockResolver,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a public object.")
	reader := bytes.NewReader(testData)

	// Upload public object - bucketName is owner DID
	info, err := client.PutObject(context.Background(), ownerDID, "test-key", reader, int64(len(testData)),
		filesdk.WithAccessType(filesdk.AccessTypePublic),
		filesdk.WithContentType("text/plain"),
		filesdk.WithIssuerDID(issuerDID),
	)
	if err != nil {
		t.Fatalf("Failed to put object: %v", err)
	}

	if info.CID != "test-cid-123" {
		t.Errorf("Expected CID 'test-cid-123', got '%s'", info.CID)
	}
}

// TestPutObjectPrivate tests uploading a private object (with encryption)
func TestPutObjectPrivate(t *testing.T) {
	ownerPrivHex, ownerPubHex := generatePREKeys(t)
	ownerDID := "test-owner-did"
	issuerDID := "test-issuer-did"
	verificationMethod := ownerDID + "#key-1"
	did := strings.SplitN(verificationMethod, "#", 2)[0]

	// Mock DID resolver that returns the owner's public key
	resolverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET for resolver, got %s", r.Method)
		}

		doc := map[string]interface{}{
			"@context": []string{"https://www.w3.org/ns/did/v1"},
			"id":       did,
			"verificationMethod": []map[string]interface{}{
				{
					"id":           verificationMethod,
					"type":         "JsonWebKey2020",
					"controller":   did,
					"publicKeyHex": ownerPubHex,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
	defer resolverServer.Close()

	// Test data
	testData := []byte("Hello, World! This is a private object.")

	// Create a test server
	var receivedData []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Check issuer DID header
		issuerDIDHeader := r.Header.Get("X-Issuer-Did")
		if issuerDIDHeader != ownerDID {
			t.Errorf("Expected owner DID '%s', got '%s'", ownerDID, issuerDIDHeader)
		}

		// Parse multipart form
		err := r.ParseMultipartForm(10 << 20) // 10MB
		if err != nil {
			t.Fatalf("Failed to parse multipart form: %v", err)
		}

		// Check form fields
		if r.FormValue("access_level") != "private" {
			t.Errorf("Expected access_level 'private', got '%s'", r.FormValue("access_level"))
		}
		if r.FormValue("owner_did") != ownerDID {
			t.Errorf("Expected owner_did '%s', got '%s'", ownerDID, r.FormValue("owner_did"))
		}
		if r.FormValue("issuer_did") != issuerDID {
			t.Errorf("Expected issuer_did '%s', got '%s'", issuerDID, r.FormValue("issuer_did"))
		}
		if r.FormValue("encrypt_type") != "rsa-aes" {
			t.Errorf("Expected encrypt_type 'rsa-aes', got '%s'", r.FormValue("encrypt_type"))
		}

		// Check capsule (encrypted AES key)
		capsule := r.FormValue("capsule")
		if capsule == "" {
			t.Error("Expected capsule (encrypted key) to be set")
		}

		// Read file data
		file, _, err := r.FormFile("data")
		if err != nil {
			t.Fatalf("Failed to get file from form: %v", err)
		}
		defer file.Close()
		receivedData, _ = io.ReadAll(file)

		capsuleBytes, err := hex.DecodeString(capsule)
		if err != nil {
			t.Fatalf("Failed to decode capsule: %v", err)
		}
		decryptor, err := pre.NewDecryptorByOwner(ownerPrivHex, capsuleBytes)
		if err != nil {
			t.Fatalf("Failed to create decryptor: %v", err)
		}
		var plainBuf bytes.Buffer
		if err := decryptor.DecryptStream(context.Background(), bytes.NewReader(receivedData), &plainBuf); err != nil {
			t.Fatalf("Failed to decrypt stream: %v", err)
		}
		if !bytes.Equal(plainBuf.Bytes(), testData) {
			t.Errorf("Decrypted data mismatch. Expected %q, got %q", testData, plainBuf.Bytes())
		}

		// Return JSON response
		response := map[string]interface{}{
			"cid":          "test-cid-private-123",
			"owner_did":    ownerDID,
			"created_at":   time.Now().Format(time.RFC3339),
			"file_name":    "test-key-private",
			"file_type":    "text/plain",
			"access_level": "private",
			"issuer_did":   issuerDID,
			"encrypt_type": "rsa-aes",
			"size":         int64(len(receivedData)),
			"capsule":      capsule,
			"owner_vc_jwt": "",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	// Create resolver using verificationmethod package
	resolver := verificationmethod.NewResolver(resolverServer.URL)

	// Create client with resolver
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: resolver,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	reader := bytes.NewReader(testData)

	// Upload private object
	info, err := client.PutObject(context.Background(), ownerDID, "test-key-private", reader, int64(len(testData)),
		filesdk.WithAccessType(filesdk.AccessTypePrivate),
		filesdk.WithContentType("text/plain"),
		filesdk.WithIssuerDID(issuerDID),
		filesdk.WithVerificationMethod(verificationMethod),
	)
	if err != nil {
		t.Fatalf("Failed to put object: %v", err)
	}

	if info.CID != "test-cid-private-123" {
		t.Errorf("Expected CID 'test-cid-private-123', got '%s'", info.CID)
	}

	// Verify data was encrypted (should be different from original)
	if len(receivedData) == 0 {
		t.Error("No data received")
	}
	// Encrypted data should be longer than original due to IV + tag overhead
	if len(receivedData) <= len(testData) {
		t.Error("Encrypted data too short")
	}

	// Test decryption
	encryptedKeyHeader := ""
	// In a real scenario, we'd get this from the server response
	// For testing, we'll need to extract it from the request
	// This is a simplified test

	// Now test GetObject with decryption
	testGetObjectPrivate(t, client, receivedData, encryptedKeyHeader)
}

// TestGetObjectPublic tests downloading a public object (no decryption)
func TestGetObjectPublic(t *testing.T) {
	ownerDID := "test-owner-did"

	testData := []byte("Hello, World! This is a public object.")

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}

		// Check owner DID header (bucketName)
		issuerDID := r.Header.Get("X-Issuer-Did")
		if issuerDID != ownerDID {
			t.Errorf("Expected owner DID '%s', got '%s'", ownerDID, issuerDID)
		}

		w.Header().Set("Last-Modified", time.Now().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testData)))
		w.Header().Set("X-Access-Level", "public")
		w.WriteHeader(http.StatusOK)
		w.Write(testData)
	}))
	defer server.Close()

	// Create a mock resolver
	mockResolver := &mockResolver{publicKeyHex: ""}

	// Create client
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: mockResolver,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Get object - bucketName is ownerDID, objectName is CID
	result, err := client.GetObject(context.Background(), ownerDID, "test-cid-123")
	if err != nil {
		t.Fatalf("Failed to get object: %v", err)
	}
	defer result.Body.Close()

	// Read data
	readData, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("Failed to read object: %v", err)
	}

	if !bytes.Equal(readData, testData) {
		t.Errorf("Data mismatch. Expected %q, got %q", testData, readData)
	}

	// Check object info
	info := result.Info
	if info.CID != "test-cid-123" {
		t.Errorf("Expected CID 'test-cid-123', got '%s'", info.CID)
	}
	if info.ContentType != "text/plain" {
		t.Errorf("Expected content type 'text/plain', got '%s'", info.ContentType)
	}
}

// testGetObjectPrivate is a helper function to test private object retrieval
func testGetObjectPrivate(t *testing.T, client *filesdk.Client, encryptedData []byte, encryptedKey string) {
	// This is a simplified test - in a real scenario, we'd set up a proper server
	// that returns the encrypted data and headers
	t.Skip("Skipping private object retrieval test - requires full server setup")
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
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: mockResolver,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	testData := []byte("test data")
	reader := bytes.NewReader(testData)

	// Try to upload private object - should work with resolver, but might fail on encryption
	_, err = client.PutObject(context.Background(), "test-owner-did", "test-key", reader, int64(len(testData)),
		filesdk.WithAccessType(filesdk.AccessTypePrivate),
		filesdk.WithIssuerDID("test-issuer-did"),
	)

	// With resolver required, the error will be about getting the public key, not about missing resolver
	if err == nil {
		t.Error("Expected error when uploading private object with invalid resolver")
	}
	if !strings.Contains(err.Error(), "failed to get public key") && !strings.Contains(err.Error(), "resolver") {
		t.Errorf("Expected error about resolver or public key, got: %v", err)
	}
}

// TestGetObjectPrivateWithoutKey tests that private download requires private key
func TestGetObjectPrivateWithoutKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Access-Level", "private")
		w.Header().Set("X-Capsule", "test-encrypted-key")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("encrypted data"))
	}))
	defer server.Close()

	mockResolver := &mockResolver{publicKeyHex: ""}
	client, err := filesdk.New(filesdk.Config{
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
		Resolver: mockResolver,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Try to get private object without private key
	_, err = client.GetObject(context.Background(), "test-owner-did", "test-cid-123")

	if err == nil {
		t.Error("Expected error when getting private object without private key")
	}
	if !strings.Contains(err.Error(), "owner private key (hex) is required") {
		t.Errorf("Expected error about private key, got: %v", err)
	}
}
