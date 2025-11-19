# File SDK

A Go SDK for interacting with IPFS gateway services, providing secure file upload and download capabilities with built-in encryption/decryption support using Proxy Re-Encryption (PRE).

## Features

- **File Upload & Download**: Upload and download files to/from IPFS gateway
- **Encryption Support**: Built-in Proxy Re-Encryption (PRE) provider, with support for custom encryption algorithms
- **Public & Private Access**: Support for both public (unencrypted) and private (encrypted) file access
- **Flexible Key Resolution**: Built-in DID resolver or implement custom public key retrieval
- **Streaming Support**: Efficient streaming encryption/decryption for large files
- **S3-like Interface**: Familiar PutObject/GetObject API similar to AWS S3

## Installation

```bash
go get github.com/dinhwe2612/file-sdk
```

## Quick Start

### Basic Usage

```go
client, err := filesdk.New(filesdk.Config{
    Endpoint: "http://localhost:8083/api/v1",
    Timeout:  30 * time.Second,
})
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

ownerDID := "did:example:owner"
issuerDID := "did:example:issuer"

// Upload a public file (bucketName = owner DID)
file, _ := os.Open("example.txt")
info, err := client.PutObject(ctx, ownerDID, "example.txt", file, 0, filesdk.PutObjectOptions{
    AccessType:  filesdk.AccessTypePublic,
    ContentType: "text/plain",
    IssuerDID:   issuerDID,
})

// Download the file
obj, err := client.GetObject(ctx, ownerDID, info.CID, filesdk.GetObjectOptions{})
// ... read from obj
```

### Uploading Private (Encrypted) Files

```go
ownerDID := "did:example:owner"
issuerDID := "did:example:issuer"

info, err := client.PutObject(ctx, ownerDID, "secret.txt", file, 0, filesdk.PutObjectOptions{
    AccessType:         filesdk.AccessTypePrivate,
    ContentType:        "text/plain",
    IssuerDID:          issuerDID,
    ResolverURL:        "https://resolver.example.com/api/v1/did",
    VerificationMethod: ownerDID + "#key-1",
})
```

### Downloading Private (Encrypted) Files

```go
obj, err := client.GetObject(ctx, ownerDID, cid, filesdk.GetObjectOptions{
    PrivateKeyHex: "owner-private-key-hex",
    Headers: http.Header{
        "Authorization": []string{"Bearer viewer-jwt-token"},
    },
})
defer obj.Close()

data, err := io.ReadAll(obj)
```

## API Reference

### Client

#### `New(cfg Config) (*Client, error)`

Creates a new File SDK client.

**Config:**
- `Endpoint` (string, required): Gateway endpoint URL
- `Timeout` (time.Duration): HTTP client timeout (default: 30s)
- `DefaultHeaders` (http.Header): Default headers for all requests
- `HTTPClient` (*http.Client): Custom HTTP client (optional)
- `CryptProvider` (crypt.Provider): Custom decryptor provider for private downloads (defaults to built-in PRE provider)

### PutObject

#### `PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, size int64, opts PutObjectOptions) (UploadInfo, error)`

Uploads a file to the gateway.

**Parameters:**
- `bucketName`: Owner DID (bucket identifier)
- `objectName`: Name of the file
- `reader`: File content reader
- `size`: File size in bytes
- `opts`: Upload options

**PutObjectOptions:**
- `AccessType` (AccessType): `AccessTypePublic` or `AccessTypePrivate` (default: public)
- `ContentType` (string): MIME type of the file
- `IssuerDID` (string, required): Issuer DID stored alongside the object
- `ResolverURL` (string): DID resolver base URL (required for private uploads unless configured globally)
- `VerificationMethod` (string): DID verification method ID used to fetch the public key (defaults to `<ownerDID>#key-1` if empty)

**Returns:**
- `UploadInfo`: Contains `CID`, `OwnerDID`, `CreatedAt`, `FileName`, `FileType`, `AccessLevel`, `IssuerDID`, `Size`, `Capsule`, and `OwnerVCJWT`

### GetObject

#### `GetObject(ctx context.Context, bucketName, objectName string, opts GetObjectOptions) (*Object, error)`

Downloads a file from the gateway.

**Parameters:**
- `bucketName`: Owner DID that was used during upload
- `objectName`: CID of the file
- `opts`: Download options

**GetObjectOptions:**
- `PrivateKeyHex` (string): Private key for decrypting private files (required for private objects when using default provider)
- `Headers` (http.Header): Custom HTTP headers (e.g., Authorization)
- `Range` (string): Byte range for partial downloads

**Returns:**
- `*Object`: Implements `io.Reader`, `io.ReaderAt`, `io.Seeker`, `io.Closer`

**Object Methods:**
- `Read([]byte) (int, error)`: Read decrypted content
- `Stat() (ObjectInfo, error)`: Get object metadata
- `Close() error`: Close the object

## Encryption

The SDK provides a flexible encryption system through the `Encryptor` and `Decryptor` interfaces. You can use the built-in Proxy Re-Encryption (PRE) provider or implement your own encryption algorithm.

### Using Built-in PRE Provider

The SDK includes a PRE (Proxy Re-Encryption) implementation that you can use out of the box:

```go
import "github.com/dinhwe2612/file-sdk/pkg/crypt"
import "github.com/dinhwe2612/file-sdk/pkg/resolver"

// Option 1: Using default resolver (resolves public key from DID)
resolver := resolver.NewResolver("https://resolver.example.com", "did:example:owner#key-1")
encryptor, err := crypt.NewPreEncryptor(crypt.PreEncryptorOptions{
    Resolver: resolver,
})

// Option 2: Using custom resolver for public key retrieval
import "github.com/dinhwe2612/file-sdk/pkg/crypt"

type myResolver struct {
    publicKey string
}
func (r *myResolver) GetPublicKey() (string, error) {
    return r.publicKey, nil
}
encryptor, err := crypt.NewPreEncryptor(crypt.PreEncryptorOptions{
    Resolver: &myResolver{publicKey: "your-public-key-hex"},
})
```

### Implementing Custom Encryption Algorithm

You can implement your own encryption algorithm by implementing the `Encryptor` and `Decryptor` interfaces:

```go
import "github.com/dinhwe2612/file-sdk/pkg/crypt"

// Implement your custom encryptor
type myEncryptor struct {
    // Your encryption key material
}

func (e *myEncryptor) Encrypt(ctx context.Context, plaintext io.Reader) (io.Reader, string, error) {
    // Your encryption logic here
    // Return encrypted stream and capsule (if needed)
    return encryptedReader, capsuleHex, nil
}

// Implement your custom decryptor
type myDecryptor struct {
    // Your decryption key material
}

func (d *myDecryptor) Decrypt(ctx context.Context, ciphertext io.Reader) (io.ReadCloser, error) {
    // Your decryption logic here
    return decryptedReader, nil
}

// Use your custom encryptor
encryptor := &myEncryptor{/* ... */}
info, err := client.PutObject(ctx, "issuer-did", "file.txt", file, 0, filesdk.PutObjectOptions{
    AccessType: filesdk.AccessTypePrivate,
    Encryptor:  encryptor, // Use your custom encryptor
    OwnerDID:   "did:example:owner",
})
```

### Decryption Providers

By default the client uses a PRE decryptor that expects the owner (or viewer) private key plus a capsule supplied by the gateway/JWT. You can customize this by providing your own `crypt.Provider` when constructing the client:

```go
vaultProv := &crypt.VaultProvider{client: vaultClient}

client, err := filesdk.New(filesdk.Config{
    Endpoint:      gatewayURL,
    CryptProvider: vaultProv, // uses Vault to derive decryptors
})
```

Custom providers allow you to pull private keys from secure stores, implement viewer-specific re-encryption flows, or plug in completely different algorithms.

## Public Key Resolution

The SDK provides flexible options for retrieving public keys. You can use the built-in DID resolver or implement your own custom resolver.

### Using Default DID Resolver

The SDK includes a DID resolver that resolves public keys from Decentralized Identifiers (DIDs):

```go
import "github.com/dinhwe2612/file-sdk/pkg/resolver"

// Create default resolver
resolver := resolver.NewResolver(
    "https://resolver.example.com",           // Resolver base URL
    "did:example:owner#verification-method-1", // Verification method URL
)

// Get public key
publicKey, err := resolver.GetPublicKey()
```

### Implementing Custom Public Key Resolver

You can implement your own resolver to retrieve public keys from any source (database, API, configuration, etc.):

```go
import "github.com/dinhwe2612/file-sdk/pkg/resolver"

// Implement the Resolver interface
type customResolver struct {
    // Your resolver state
    publicKey string
}

func (r *customResolver) GetPublicKey() (string, error) {
    // Your custom logic to retrieve public key
    // Could be from database, API, config file, etc.
    return r.publicKey, nil
}

// Use your custom resolver
myResolver := &customResolver{publicKey: "your-public-key-hex"}
encryptor, err := crypt.NewPreEncryptor(crypt.PreEncryptorOptions{
    Resolver: myResolver,
})
```

### Public Key Retrieval Options

1. **Default DID Resolver**: Resolves public keys from DID documents via HTTP
2. **Custom Resolver**: Implement `resolver.Resolver` interface for any key source
3. **Direct Public Key**: Pass public key directly through a custom resolver implementation

## Examples

See the `examples/` directory for complete working examples:

- **Basic upload/download**: Simple file operations
- **Encrypted upload**: Uploading private files with encryption
- **Encrypted download**: Downloading and decrypting private files

## Architecture

### Package Structure

```
file-sdk/
├── api.go              # Client initialization and configuration
├── api-put-object.go   # File upload implementation
├── api-get-object.go   # File download implementation
├── pkg/
│   ├── crypt/          # Encryption/decryption
│   │   ├── provider.go # Encryptor/Decryptor interfaces
│   │   └── pre_provider.go # PRE implementation
│   ├── resolver/       # DID resolver
│   │   └── resolver.go
│   └── credential/     # JWT credential handling
│       └── jwt.go
└── examples/           # Example code
```

### Key Components

1. **Client**: Main SDK client for file operations
2. **Encryptor/Decryptor Interfaces**: Abstract interfaces allowing any encryption algorithm implementation
3. **PRE Provider**: Built-in Proxy Re-Encryption implementation (can be replaced with custom algorithms)
4. **Resolver Interface**: Abstract interface for public key retrieval (default DID resolver included)
5. **DID Resolver**: Default implementation that resolves public keys from DID documents

## Requirements

- Go 1.24.6 or higher
- Access to an IPFS gateway endpoint
- For private files: DID resolver endpoint (optional if using custom resolver)
