package filesdk

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/credential"
	"github.com/pilacorp/nda-auth-sdk/provider"
	pre "github.com/pilacorp/nda-reencryption-sdk/pre"
)

// PutObjectOpt configures PutObject call options.
type PutObjectOpt func(*putObjectOptions)

// putObjectOptions holds configuration for PutObject call.
type putObjectOptions struct {
	encryptorChunkSize int
	issuerPrivKeyHex   string
	signOptions        []provider.SignOption
}

// WithEncryptorChunkSize sets the chunk size for PRE encryption.
// If not provided, defaults to encryptorChunkSize (1MB).
func WithEncryptorChunkSize(chunkSize int) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.encryptorChunkSize = chunkSize
	}
}

// WithUploadApplicationPrivKeyHex sets application signing options used when creating the upload VP token.
func WithUploadApplicationPrivKeyHex(privKeyHex string) PutObjectOpt {
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return func(o *putObjectOptions) {}
	}

	return func(o *putObjectOptions) {
		o.signOptions = append(o.signOptions, provider.WithPrivateKey(privKeyBytes))
	}
}

// WithIssuerPrivKeyHex sets the Priv key hex of the issuer.
func WithIssuerPrivKeyHex(privKeyHex string) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.issuerPrivKeyHex = privKeyHex
	}
}

// getPutObjectOptions returns the putObjectOptions with defaults applied.
func getPutObjectOptions(opts ...PutObjectOpt) *putObjectOptions {
	options := &putObjectOptions{
		encryptorChunkSize: encryptorChunkSize,
		issuerPrivKeyHex:   "",
		signOptions:        nil,
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
	Capsule     string    `json:"capsule,omitempty"`
	OwnerVCJWT  string    `json:"owner_vc_jwt"`
}

// PutObjectInput contains all parameters for uploading an object.
type PutObjectInput struct {
	// Bucket is the owner DID (required).
	Bucket *string
	// Key is the object name (required).
	Key *string
	// Body is the object data stream (required).
	Body io.Reader
	// Metadata contains additional metadata key-value pairs.
	// If "Authorization" is present, it will be used as the authorization header.
	Metadata map[string]string
	// AccessType determines if the object is public or Priv (default: AccessTypePublic).
	AccessType AccessType
	// IssuerDID is the DID of the issuer (required).
	IssuerDID *string
	// ContentType is the MIME type of the object (optional, default: "application/octet-stream").
	ContentType *string
}

type PutObjectOutput struct {
	SSEKMSEncryptionContext *string
}

// PutObject creates an object in a bucket with optional encryption.
// Bucket represents the owner DID, and the returned CID is used as the object key.
func (c *Client) PutObject(
	ctx context.Context,
	input *PutObjectInput,
	opts ...PutObjectOpt,
) (*PutObjectOutput, error) {
	options := getPutObjectOptions(opts...)

	// Get bucket
	if input.Bucket == nil || *input.Bucket == "" {
		return nil, errors.New("filesdk: owner DID (Bucket) is required")
	}

	// Get key
	if input.Key == nil || *input.Key == "" {
		return nil, errors.New("filesdk: object name (Key) is required")
	}

	// Get body
	if input.Body == nil {
		return nil, errors.New("filesdk: body is required")
	}

	// Get issuer DID
	if input.IssuerDID == nil || *input.IssuerDID == "" {
		return nil, errors.New("filesdk: issuer DID is required")
	}

	// Get issuer Priv key hex
	issuerPrivKeyHex := ""
	if options.issuerPrivKeyHex != "" {
		issuerPrivKeyHex = options.issuerPrivKeyHex
	} else if c.issuerPrivKeyHex != nil {
		issuerPrivKeyHex = *c.issuerPrivKeyHex
	}
	if issuerPrivKeyHex == "" {
		return nil, errors.New("filesdk: issuer Priv key hex is not configured")
	}

	// Get application DID
	if c.appDID == "" {
		return nil, errors.New("filesdk: application DID is not configured")
	}

	// Get gateway trust JWT
	if c.gatewayTrustJWT == "" {
		return nil, errors.New("filesdk: gateway trust JWT is not configured")
	}

	// Get accessible schema URL
	if c.accessibleSchemaURL == nil || *c.accessibleSchemaURL == "" {
		return nil, errors.New("filesdk: accessible schema URL is not configured")
	}

	// Determine access level from AccessType.
	accessLevel := "public"
	if input.AccessType == AccessTypePrivate {
		accessLevel = "private"
	}

	// Build the data source (possibly encrypted)
	bodyReader := input.Body
	capsuleHex := ""

	if input.AccessType == AccessTypePrivate {
		verificationMethod := *input.Bucket + "#key-1"
		publicKeyHex, err := c.resolver.GetPublicKey(verificationMethod)
		if err != nil {
			return nil, fmt.Errorf("filesdk: failed to get public key from resolver: %w", err)
		}

		enc, capsule, err := pre.NewEncryptor(publicKeyHex, uint32(options.encryptorChunkSize))
		if err != nil {
			return nil, fmt.Errorf("filesdk: failed to create encryptor: %w", err)
		}

		encR, encW := io.Pipe()

		// Encrypt in background: reader -> enc -> encW
		go func(r io.Reader, w *io.PipeWriter) {
			if err := enc.EncryptStream(ctx, r, w); err != nil {
				_ = w.CloseWithError(fmt.Errorf("filesdk: encrypt stream failed: %w", err))
				return
			}
			_ = w.Close()
		}(bodyReader, encW)

		bodyReader = encR
		capsuleHex = hex.EncodeToString(capsule)
	}

	// Build streaming multipart body via io.Pipe
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	// Start the multipart writer in a goroutine
	go func() {
		err := func() error {
			defer writer.Close()

			// Form fields
			if err := writer.WriteField("issuer_did", *input.IssuerDID); err != nil {
				return fmt.Errorf("filesdk: failed to write issuer_did field: %w", err)
			}
			if err := writer.WriteField("owner_did", *input.Bucket); err != nil {
				return fmt.Errorf("filesdk: failed to write owner_did field: %w", err)
			}
			if err := writer.WriteField("access_level", accessLevel); err != nil {
				return fmt.Errorf("filesdk: failed to write access_level field: %w", err)
			}

			if input.AccessType == AccessTypePrivate && capsuleHex != "" {
				if err := writer.WriteField("capsule", capsuleHex); err != nil {
					return fmt.Errorf("filesdk: failed to write capsule field: %w", err)
				}
			}

			// File part
			contentType := ""
			if input.ContentType != nil {
				contentType = *input.ContentType
			}
			if contentType == "" {
				contentType = "application/octet-stream"
			}

			fileHeader := textproto.MIMEHeader{}
			fileHeader.Set(
				"Content-Disposition",
				fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "data", *input.Key),
			)
			fileHeader.Set("Content-Type", contentType)

			part, err := writer.CreatePart(fileHeader)
			if err != nil {
				return fmt.Errorf("filesdk: failed to create form file: %w", err)
			}

			buf := make([]byte, copyBufferSize)
			if _, err := io.CopyBuffer(part, bodyReader, buf); err != nil {
				return fmt.Errorf("filesdk: failed to copy data to form: %w", err)
			}

			return nil
		}()
		if err != nil {
			slog.ErrorContext(ctx, "put object -> failed to write form fields", "error", err)

			_ = pw.CloseWithError(err)

			return
		}

		if err := pw.Close(); err != nil {
			slog.ErrorContext(ctx, "put object -> failed to close writer", "error", err)

			return
		}
	}()

	// Build request & headers
	targetURL := fmt.Sprintf("%s/files/upload", c.endpoint.String())

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, pr)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to create request: %w", err)
	}

	// Set headers from metadata
	headers := make(http.Header)
	if input.Metadata != nil {
		for k, v := range input.Metadata {
			headers.Set(k, v)
		}
	}
	c.mergeHeaders(req.Header, headers)

	// Set content type
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Get authorization from headers
	authorization := strings.TrimSpace(req.Header.Get(headerAuthorization))
	if authorization == "" {
		return nil, errors.New("filesdk: authorization header is required")
	}

	vpToken, _, err := c.buildVPAuthorization(ctx, authorization, *input.IssuerDID, options.signOptions...)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to build VP authorization: %w", err)
	}

	req.Header.Set(headerAuthorization, vpToken)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, fmt.Errorf("filesdk: upload failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	// Decode upload response first to get CID
	var uploadResp UploadInfo
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return nil, fmt.Errorf("filesdk: failed to decode response: %w", err)
	}

	// Create owner file credential if we have a CID and schema configured
	if uploadResp.CID != "" {
		ownerVCJWT, err := credential.CreateOwnerFileCredential(
			ctx,
			uploadResp.CID,
			*input.IssuerDID,
			*input.Bucket,
			capsuleHex,
			*c.accessibleSchemaURL,
			issuerPrivKeyHex,
		)
		if err != nil {
			return nil, fmt.Errorf("filesdk: failed to create owner file credential: %w", err)
		}
		uploadResp.OwnerVCJWT = ownerVCJWT
	}

	// make UploadInfo to string json
	uploadInfoJSON, err := json.Marshal(uploadResp)
	if err != nil {
		return nil, fmt.Errorf("filesdk: failed to marshal upload info: %w", err)
	}

	infoString := string(uploadInfoJSON)

	return &PutObjectOutput{
		SSEKMSEncryptionContext: &infoString,
	}, nil
}
