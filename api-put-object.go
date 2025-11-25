package filesdk

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/dinhwe2612/file-sdk/pkg/credential"
	"github.com/pilacorp/nda-auth-sdk/provider"
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
	signOptions        []provider.SignOption
	headers            http.Header
	accessibleSchemaID string
	pilaAuthURL        string
}

// WithAccessType sets the access type (public or private).
func WithAccessType(accessType AccessType) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.accessType = accessType
	}
}

// WithContentType sets the content type of the object (for the file part).
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

// WithSignOptions sets the sign options (appended, not replaced).
func WithSignOptions(signOptions ...provider.SignOption) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.signOptions = append(o.signOptions, signOptions...)
	}
}

// WithHeaders sets additional HTTP headers for the upload request.
func WithHeaders(headers http.Header) PutObjectOpt {
	return func(o *putObjectOptions) {
		if headers == nil {
			o.headers = make(http.Header)
			return
		}
		o.headers = cloneHeader(headers)
	}
}

// WithAccessibleSchemaID sets the accessible schema ID.
func WithAccessibleSchemaID(id string) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.accessibleSchemaID = id
	}
}

// WithPilaAuthURL sets the Pila auth URL.
func WithPilaAuthURL(url string) PutObjectOpt {
	return func(o *putObjectOptions) {
		o.pilaAuthURL = url
	}
}

// getPutObjectOptions returns the putObjectOptions with defaults applied.
func getPutObjectOptions(opts ...PutObjectOpt) *putObjectOptions {
	options := &putObjectOptions{
		accessType:         AccessTypePublic,
		contentType:        "",
		issuerDID:          "",
		verificationMethod: "",
		encryptorChunkSize: encryptorChunkSize,
		signOptions:        nil,
		headers:            nil,
	}

	for _, opt := range opts {
		opt(options)
	}

	if options.headers == nil {
		options.headers = make(http.Header)
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
func (c *Client) PutObject(
	ctx context.Context,
	bucketName, objectName string,
	reader io.Reader,
	size int64, // not enforced; streaming only
	opts ...PutObjectOpt,
) (UploadInfo, error) {
	if bucketName == "" {
		return UploadInfo{}, errors.New("filesdk: owner DID (bucketName) is required")
	}

	options := getPutObjectOptions(opts...)
	if options.issuerDID == "" {
		return UploadInfo{}, errors.New("filesdk: issuer DID is required (use WithIssuerDID)")
	}
	if objectName == "" {
		return UploadInfo{}, errors.New("filesdk: objectName is required")
	}
	if applicationDID == "" {
		return UploadInfo{}, errors.New("filesdk: application DID is not configured (use SetApplicationDID)")
	}
	if gatewayTrustJWT == "" {
		return UploadInfo{}, errors.New("filesdk: gateway trust JWT is not configured (use SetGatewayTrustJWT)")
	}

	// Determine access level from AccessType.
	accessLevel := "public"
	if options.accessType == AccessTypePrivate {
		accessLevel = "private"
	}

	// Build the data source (possibly encrypted)
	bodyReader := reader
	capsuleHex := ""

	if options.accessType == AccessTypePrivate {
		verificationMethod := bucketName + "#key-1"
		if options.verificationMethod != "" {
			verificationMethod = options.verificationMethod
		}

		publicKeyHex, err := c.resolver.GetPublicKey(verificationMethod)
		if err != nil {
			return UploadInfo{}, fmt.Errorf("filesdk: failed to get public key from resolver: %w", err)
		}

		if options.encryptorChunkSize <= 0 {
			options.encryptorChunkSize = encryptorChunkSize
		}

		enc, capsule, err := pre.NewEncryptor(publicKeyHex, uint32(options.encryptorChunkSize))
		if err != nil {
			return UploadInfo{}, fmt.Errorf("filesdk: failed to create encryptor: %w", err)
		}

		encR, encW := io.Pipe()

		// Encrypt in background: reader -> enc -> encW
		go func(r io.Reader, w *io.PipeWriter) {
			if err := enc.EncryptStream(ctx, r, w); err != nil {
				_ = w.CloseWithError(fmt.Errorf("filesdk: encrypt stream failed: %w", err))
				return
			}
			_ = w.Close()
		}(reader, encW)

		bodyReader = encR
		capsuleHex = hex.EncodeToString(capsule)
	}

	// Build streaming multipart body via io.Pipe
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	// Start the multipart writer in a goroutine
	go func() {
		defer func() {
			_ = writer.Close()
			_ = pw.Close()
		}()

		// Form fields
		if err := writer.WriteField("issuer_did", options.issuerDID); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("filesdk: failed to write issuer_did field: %w", err))
			return
		}
		if err := writer.WriteField("owner_did", bucketName); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("filesdk: failed to write owner_did field: %w", err))
			return
		}
		if err := writer.WriteField("access_level", accessLevel); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("filesdk: failed to write access_level field: %w", err))
			return
		}

		if options.accessType == AccessTypePrivate && capsuleHex != "" {
			if err := writer.WriteField("capsule", capsuleHex); err != nil {
				_ = pw.CloseWithError(fmt.Errorf("filesdk: failed to write capsule field: %w", err))
				return
			}
		}

		// File part
		contentType := options.contentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}

		fileHeader := textproto.MIMEHeader{}
		fileHeader.Set(
			"Content-Disposition",
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "data", objectName),
		)
		fileHeader.Set("Content-Type", contentType)

		part, err := writer.CreatePart(fileHeader)
		if err != nil {
			_ = pw.CloseWithError(fmt.Errorf("filesdk: failed to create form file: %w", err))
			return
		}

		buf := make([]byte, copyBufferSize)
		if _, err := io.CopyBuffer(part, bodyReader, buf); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("filesdk: failed to copy data to form: %w", err))
			return
		}
	}()

	// Build request & headers
	targetURL := fmt.Sprintf("%s/files/upload", c.endpoint.String())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, pr)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("filesdk: failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Apply caller headers first (including their original Authorization)
	for key, values := range options.headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	// Get authorization from headers
	authorization := strings.TrimSpace(req.Header.Get(headerAuthorization))
	if authorization == "" {
		return UploadInfo{}, errors.New("filesdk: authorization header is required")
	}

	// Verify authorization
	_, requester, vcJWTs, err := c.authClient.VerifyToken(ctx, authorization)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("filesdk: failed to verify authorization: %w", err)
	}
	if requester != options.issuerDID {
		return UploadInfo{}, fmt.Errorf(
			"filesdk: requester DID %q does not match issuer DID %q",
			requester, options.issuerDID,
		)
	}

	// Append VC JWTs with gateway trust
	vcJWTs = append(vcJWTs, gatewayTrustJWT)

	// Create VP token
	vpToken, err := c.authClient.CreateToken(ctx, vcJWTs, applicationDID, options.signOptions...)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("filesdk: failed to create VP token: %w", err)
	}

	vpToken = strings.TrimSpace(vpToken)
	vpToken = strings.Trim(vpToken, `"`)

	req.Header.Set(headerAuthorization, vpToken)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return UploadInfo{}, fmt.Errorf("filesdk: failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return UploadInfo{}, fmt.Errorf("filesdk: upload failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	// Decode upload response first to get CID
	var uploadResp UploadInfo
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		return UploadInfo{}, fmt.Errorf("filesdk: failed to decode response: %w", err)
	}

	// Create owner file credential if we have a CID and schema configured
	if uploadResp.CID != "" {
		// use default or options
		accessibleSchemaID := options.accessibleSchemaID
		if accessibleSchemaID == "" {
			accessibleSchemaID = c.accessibleSchemaID
		}

		pilaAuthURL := options.pilaAuthURL
		if pilaAuthURL == "" {
			pilaAuthURL = c.pilaAuthURL
		}

		credential.SetAccessibleSchemaID(accessibleSchemaID)
		credential.SetPilaAuthURL(pilaAuthURL)

		ownerVCJWT, err := credential.CreateOwnerFileCredential(ctx, uploadResp.CID, options.issuerDID, bucketName, capsuleHex)
		if err != nil {
			return UploadInfo{}, fmt.Errorf("filesdk: failed to create owner file credential: %w", err)
		}
		uploadResp.OwnerVCJWT = ownerVCJWT
	}

	return uploadResp, nil
}
