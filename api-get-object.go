package filesdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/dinhwe2612/file-sdk/pkg/credential"
	"github.com/dinhwe2612/file-sdk/pkg/crypt"
)

// GetObjectOptions represents options for GetObject call
type GetObjectOptions struct {
	// privateKeyHex is the hex-encoded private key for decrypting private objects.
	// Required when fetching private objects.
	PrivateKeyHex string
	// Headers
	Headers http.Header
	// Range
	Range string
}

// ObjectInfo contains information about an object
type ObjectInfo struct {
	ETag        string
	Key         string
	Size        int64
	ContentType string
	Metadata    http.Header
}

// Object represents an open object. It implements
// Reader, ReaderAt, Seeker, Closer for a HTTP stream.
type Object struct {
	// Mutex for thread safety
	mutex *sync.Mutex

	// Context and cancel
	ctx    context.Context
	cancel context.CancelFunc

	// HTTP response
	httpReader io.ReadCloser
	objectInfo ObjectInfo

	// Current offset
	currOffset int64

	// State flags
	isClosed bool
	prevErr  error
}

// GetObject retrieves an object from storage.
// bucketName represents the owner DID, objectName is the CID.
func (c *Client) GetObject(ctx context.Context, bucketName, objectName string, opts GetObjectOptions) (*Object, error) {
	if bucketName == "" {
		return nil, errors.New("owner DID (bucketName) is required")
	}
	if objectName == "" {
		return nil, errors.New("object name (CID) is required")
	}

	// Build URL for IPFS endpoint - objectName (CID) is used as path parameter
	target := c.endpoint.ResolveReference(&url.URL{
		Path: path.Join(c.endpoint.Path, "files", objectName),
	})

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers - bucketName carries the owner DID
	req.Header.Set("X-Issuer-Did", bucketName)
	c.mergeHeaders(req.Header, opts.Headers)
	if opts.Range != "" {
		req.Header.Set("Range", opts.Range)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		return nil, fmt.Errorf("get object failed: status=%d", resp.StatusCode)
	}

	// Parse object info from headers
	etag := objectName // Use CID as ETag
	contentType := resp.Header.Get("Content-Type")
	contentLength := resp.ContentLength

	objectInfo := ObjectInfo{
		ETag:        etag,
		Key:         objectName, // CID
		Size:        contentLength,
		ContentType: contentType,
		Metadata:    cloneHeader(resp.Header),
	}

	// Create context with cancel
	gctx, cancel := context.WithCancel(ctx)

	// Check access level from response header (X-Access-Level)
	// The server returns "private" or "public" in X-Access-Level header
	accessLevel := resp.Header.Get("X-Access-Level")

	// Extract capsule from JWT token instead of response header
	var capsule string
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		// Extract JWT token from Authorization header (could be "Bearer <token>" or just "<token>")
		jwtToken := strings.TrimPrefix(authHeader, "Bearer ")
		jwtToken = strings.TrimSpace(jwtToken)

		if jwtToken != "" {
			capsule, _ = credential.CapsuleFromJWT(jwtToken)
			println("capsule from jwt", capsule)
		}
	}

	var reader io.ReadCloser = resp.Body

	// If object is private and we have a private key, decrypt
	if accessLevel == "private" {
		if opts.PrivateKeyHex == "" {
			cancel()
			resp.Body.Close()
			return nil, errors.New("owner private key (hex) is required for private objects")
		}

		if capsule == "" {
			cancel()
			resp.Body.Close()
			return nil, errors.New("encrypted capsule is missing for private object")
		}

		decryptor, err := c.cryptProvider.NewPreDecryptor(gctx, capsule, crypt.ProviderOpts{
			PrivateKeyHex: opts.PrivateKeyHex,
		})
		if err != nil {
			cancel()
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decrypt object: %w", err)
		}

		reader, err = decryptor.Decrypt(gctx, resp.Body)
		if err != nil {
			cancel()
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decrypt object: %w", err)
		}
	}

	obj := &Object{
		mutex:      &sync.Mutex{},
		ctx:        gctx,
		cancel:     cancel,
		httpReader: reader,
		objectInfo: objectInfo,
		currOffset: 0,
		isClosed:   false,
	}

	return obj, nil
}

// Read reads up to len(b) bytes into b. It returns the number of
// bytes read (0 <= n <= len(b)) and any error encountered. Returns
// io.EOF upon end of file.
func (o *Object) Read(b []byte) (n int, err error) {
	if o == nil {
		return 0, errors.New("object is nil")
	}

	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.prevErr != nil || o.isClosed {
		return 0, o.prevErr
	}

	n, err = o.httpReader.Read(b)
	if err != nil && err != io.EOF {
		o.prevErr = err
		return n, err
	}

	o.currOffset += int64(n)

	if err == io.EOF {
		o.prevErr = io.EOF
	}

	return n, err
}

// ReadAt reads len(b) bytes from the File starting at byte offset
// off. It returns the number of bytes read and the error, if any.
// ReadAt always returns a non-nil error when n < len(b). At end of
// file, that error is io.EOF.
func (o *Object) ReadAt(b []byte, offset int64) (n int, err error) {
	if o == nil {
		return 0, errors.New("object is nil")
	}

	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.prevErr != nil && o.prevErr != io.EOF || o.isClosed {
		return 0, o.prevErr
	}

	// For ReadAt, we need to seek to the offset first
	// This is a simplified implementation
	// In a full implementation, this would use Range requests
	if offset != o.currOffset {
		// For encrypted objects, we can't easily seek
		// This would require re-fetching with Range header
		return 0, errors.New("ReadAt not fully supported for encrypted objects")
	}

	return o.Read(b)
}

// Seek sets the offset for the next Read or Write to offset,
// interpreted according to whence: 0 means relative to the
// origin of the file, 1 means relative to the current offset,
// and 2 means relative to the end.
// Seek returns the new offset and an error, if any.
func (o *Object) Seek(offset int64, whence int) (n int64, err error) {
	if o == nil {
		return 0, errors.New("object is nil")
	}

	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.prevErr != nil && o.prevErr != io.EOF {
		return 0, o.prevErr
	}

	var newOffset int64
	switch whence {
	case io.SeekStart:
		if offset < 0 {
			return 0, errors.New("negative position not allowed")
		}
		newOffset = offset
	case io.SeekCurrent:
		newOffset = o.currOffset + offset
	case io.SeekEnd:
		if o.objectInfo.Size < 0 {
			return 0, errors.New("seek end not supported when object size is unknown")
		}
		newOffset = o.objectInfo.Size + offset
	default:
		return 0, fmt.Errorf("invalid whence %d", whence)
	}

	if newOffset < 0 {
		return 0, errors.New("negative position not allowed")
	}

	o.currOffset = newOffset
	o.prevErr = nil

	return o.currOffset, nil
}

// Stat returns the ObjectInfo structure describing Object.
func (o *Object) Stat() (ObjectInfo, error) {
	if o == nil {
		return ObjectInfo{}, errors.New("object is nil")
	}

	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.prevErr != nil && o.prevErr != io.EOF || o.isClosed {
		return ObjectInfo{}, o.prevErr
	}

	return o.objectInfo, nil
}

// Close closes the object and releases any resources.
// The behavior of Close after the first call returns error
// for subsequent Close() calls.
func (o *Object) Close() (err error) {
	if o == nil {
		return errors.New("object is nil")
	}

	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.isClosed {
		return o.prevErr
	}

	o.cancel()

	if o.httpReader != nil {
		err = o.httpReader.Close()
	}

	o.isClosed = true
	o.prevErr = errors.New("object is already closed")

	return err
}
