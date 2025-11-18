package filesdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/crypt"
	"github.com/dinhwe2612/file-sdk/pkg/resolver"
)

// AccessType represents the access type of an object
type AccessType string

const (
	// AccessTypePublic indicates the object is public (no encryption)
	AccessTypePublic AccessType = "public"
	// AccessTypePrivate indicates the object is private (encrypted)
	AccessTypePrivate AccessType = "private"
)

// PutObjectOptions represents options specified by user for PutObject call
type PutObjectOptions struct {
	// AccessType specifies whether the object is public or private
	// Default is "public"
	AccessType AccessType
	// ContentType specifies the content type of the object
	ContentType string
	// IssuerDID is the issuer DID (required)
	IssuerDID string
	// Resolver url
	ResolverURL string
	// Verification method
	VerificationMethod string
}

// UploadInfo contains information about the uploaded object
type UploadInfo struct {
	Bucket string
	Key    string
	ETag   string
	Size   int64
}

// PutObject creates an object in a bucket with optional encryption.
// bucketName represents the owner DID, and the returned CID is used as the object key.
func (c *Client) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, size int64, opts PutObjectOptions) (info UploadInfo, err error) {
	if bucketName == "" {
		return UploadInfo{}, errors.New("owner DID (bucketName) is required")
	}
	if opts.IssuerDID == "" {
		return UploadInfo{}, errors.New("issuer DID (IssuerDID) is required")
	}

	// Validate and set default access type
	if opts.AccessType == "" {
		opts.AccessType = AccessTypePublic
	}

	// Determine access level from AccessType
	accessLevel := "public"
	if opts.AccessType == AccessTypePrivate {
		accessLevel = "private"
	}

	// Use default verification method if not provided
	verificationMethod := bucketName + "#key-1"
	if opts.VerificationMethod != "" {
		verificationMethod = opts.VerificationMethod
	}

	// Use default resolver url if not provided
	resolverUrl := c.resolverUrl
	if opts.ResolverURL != "" {
		resolverUrl = opts.ResolverURL
	}

	// Encrypt if private
	var bodyReader io.Reader = reader
	var encryptedAESKey string
	if opts.AccessType == AccessTypePrivate {
		encryptor, err := crypt.NewPreEncryptor(crypt.PreEncryptorOptions{
			Resolver: resolver.NewResolver(resolverUrl, verificationMethod),
		})
		if err != nil {
			return UploadInfo{}, fmt.Errorf("failed to create pre encryptor: %w", err)
		}

		bodyReader, encryptedAESKey, err = encryptor.Encrypt(ctx, reader)
		if err != nil {
			return UploadInfo{}, fmt.Errorf("failed to encrypt object: %w", err)
		}
	}

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add form fields
	writer.WriteField("issuer_did", opts.IssuerDID)
	writer.WriteField("owner_did", bucketName)
	writer.WriteField("access_level", accessLevel)

	// Use encrypted AES key as capsule if private, otherwise use provided capsule
	if opts.AccessType == AccessTypePrivate && encryptedAESKey != "" {
		writer.WriteField("capsule", encryptedAESKey)
	}
	if opts.AccessType == AccessTypePrivate {
		writer.WriteField("encrypt_type", "rsa-aes")
	}

	// Add file field
	contentType := opts.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	part, err := writer.CreateFormFile("data", objectName)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("failed to create form file: %w", err)
	}

	// Copy data to form
	if _, err := io.Copy(part, bodyReader); err != nil {
		return UploadInfo{}, fmt.Errorf("failed to copy data to form: %w", err)
	}

	writer.Close()

	// Build URL for IPFS endpoint
	targetURL := c.endpoint.ResolveReference(&url.URL{
		Path: path.Join(c.endpoint.Path, "files/upload"),
	})

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL.String(), &buf)
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
	var uploadResp struct {
		CID         string    `json:"cid"`
		OwnerDID    string    `json:"owner_did"`
		CreatedAt   time.Time `json:"created_at"`
		FileName    string    `json:"file_name"`
		FileType    string    `json:"file_type"`
		AccessLevel string    `json:"access_level"`
		IssuerDID   string    `json:"issuer_did"`
		EncryptType string    `json:"encrypt_type"`
		Size        int64     `json:"size"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return UploadInfo{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return UploadInfo{
		Bucket: bucketName,     // issuerDID
		Key:    uploadResp.CID, // CID is the object key
		ETag:   uploadResp.CID, // Use CID as ETag
		Size:   uploadResp.Size,
	}, nil
}
