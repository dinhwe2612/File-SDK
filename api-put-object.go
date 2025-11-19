package filesdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	pre "github.com/pilacorp/nda-reencryption-sdk/pre"
)

// AccessType represents the access type of an object
type AccessType string

const (
	// AccessTypePublic indicates the object is public (no encryption)
	AccessTypePublic AccessType = "public"
	// AccessTypePrivate indicates the object is private (encrypted)
	AccessTypePrivate AccessType = "private"

	// copyBufferSize is the buffer size used for copying data to multipart form.
	// 64KB is a good balance between memory usage and performance for file uploads.
	copyBufferSize = 64 * 1024

	// encryptorChunkSize is the chunk size used for PRE encryption.
	// 1MB chunk size provides good performance for encrypted file uploads.
	encryptorChunkSize = 1 << 20 // 1MB
)

// PutObjectOpt configures PutObject call options.
type PutObjectOpt func(*putObjectOptions)

// putObjectOptions holds configuration for PutObject call.
type putObjectOptions struct {
	accessType         AccessType
	contentType        string
	issuerDID          string
	verificationMethod string
	encryptorChunkSize int
}

// WithAccessType sets the access type (public or private).
func WithAccessType(accessType AccessType) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.accessType = accessType
	}
}

// WithContentType sets the content type of the object.
func WithContentType(contentType string) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.contentType = contentType
	}
}

// WithIssuerDID sets the issuer DID (required).
func WithIssuerDID(issuerDID string) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.issuerDID = issuerDID
	}
}

// WithVerificationMethod sets the verification method URL (e.g., "did:example:123#key-1").
// If not provided, defaults to "<ownerDID>#key-1".
func WithVerificationMethod(verificationMethod string) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.verificationMethod = verificationMethod
	}
}

// WithEncryptorChunkSize sets the chunk size for PRE encryption.
// If not provided, defaults to encryptorChunkSize (1MB).
func WithEncryptorChunkSize(chunkSize int) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.encryptorChunkSize = chunkSize
	}
}

// getPutObjectOptions returns the putObjectOptions with defaults applied.
func getPutObjectOptions(opts ...PutObjectOpt) *putObjectOptions {
	options := &putObjectOptions{
		accessType:         AccessTypePublic,
		contentType:        "",
		issuerDID:          "",
		verificationMethod: "",
		encryptorChunkSize: encryptorChunkSize, // Default to constant
	}

	for _, opt := range opts {
		opt(options)
	}

	return options
}

// UploadInfo contains information about the uploaded object
type UploadInfo struct {
	CID         string    `json:"cid"`
	OwnerDID    string    `json:"owner_did"`
	CreatedAt   time.Time `json:"created_at"`
	FileName    string    `json:"file_name"`
	FileType    string    `json:"file_type"`
	AccessLevel string    `json:"access_level"`
	IssuerDID   string    `json:"issuer_did"`
	Size        int64     `json:"size"`
	Capsule     string    `json:"capsule,omitempty"`
	OwnerVCJWT  string    `json:"owner_vc_jwt"`
}

// PutObject creates an object in a bucket with optional encryption.
// bucketName represents the owner DID, and the returned CID is used as the object key.
func (c *Client) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, size int64, opts ...PutObjectOpt) (info UploadInfo, err error) {
	if bucketName == "" {
		return UploadInfo{}, errors.New("owner DID (bucketName) is required")
	}

	// Parse options
	options := getPutObjectOptions(opts...)

	if options.issuerDID == "" {
		return UploadInfo{}, errors.New("issuer DID is required (use WithIssuerDID option)")
	}

	// Determine access level from AccessType
	accessLevel := "public"
	if options.accessType == AccessTypePrivate {
		accessLevel = "private"
	}

	// Encrypt if private
	var bodyReader io.Reader = reader
	var encryptedAESKey string
	if options.accessType == AccessTypePrivate {
		// Use default verification method if not provided
		verificationMethod := bucketName + "#key-1"
		if options.verificationMethod != "" {
			verificationMethod = options.verificationMethod
		}

		// Get public key from resolver
		publicKeyHex, err := c.resolver.GetPublicKey(verificationMethod)
		if err != nil {
			return UploadInfo{}, fmt.Errorf("failed to get public key from resolver: %w", err)
		}

		// Create encryptor directly with public key
		enc, capsule, err := pre.NewEncryptor(publicKeyHex, uint32(options.encryptorChunkSize))
		if err != nil {
			return UploadInfo{}, fmt.Errorf("failed to create encryptor: %w", err)
		}

		// Encrypt the data stream
		pipeReader, pipeWriter := io.Pipe()
		go func() {
			defer pipeWriter.Close()
			if err := enc.EncryptStream(ctx, reader, pipeWriter); err != nil {
				pipeWriter.CloseWithError(err)
			}
		}()

		bodyReader = pipeReader
		encryptedAESKey = hex.EncodeToString(capsule)
	}

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add form fields
	writer.WriteField("issuer_did", options.issuerDID)
	writer.WriteField("owner_did", bucketName)
	writer.WriteField("access_level", accessLevel)

	// Use encrypted AES key as capsule if private, otherwise use provided capsule
	if options.accessType == AccessTypePrivate && encryptedAESKey != "" {
		writer.WriteField("capsule", encryptedAESKey)
	}
	if options.accessType == AccessTypePrivate {
		writer.WriteField("encrypt_type", "rsa-aes")
	}

	// Add file field
	contentType := options.contentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	part, err := writer.CreateFormFile("data", objectName)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("failed to create form file: %w", err)
	}

	// Use CopyBuffer for better performance with large files
	copyBuf := make([]byte, copyBufferSize)
	if _, err := io.CopyBuffer(part, bodyReader, copyBuf); err != nil {
		return UploadInfo{}, fmt.Errorf("failed to copy data to form: %w", err)
	}

	writer.Close()

	// Build URL for file upload endpoint
	// The endpoint already includes /api/v1, so we just append /files/upload
	targetURL := fmt.Sprintf("%s/files/upload", c.endpoint.String())

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, &buf)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers - bucketName is used as issuerDID
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Issuer-Did", bucketName)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return UploadInfo{}, fmt.Errorf("upload failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	// Parse JSON response
	var uploadResp UploadInfo
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return UploadInfo{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return uploadResp, nil
}
