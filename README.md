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
import (
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/dinhwe2612/file-sdk"
)

client, err := filesdk.New(filesdk.Config{
    Endpoint:            aws.String("http://localhost:8083"),
    Timeout:             30 * time.Second,
    DIDResolverURL:      aws.String("https://resolver.example.com/api/v1/did"),
    ApplicationDID:      aws.String("did:example:app"),
    GatewayTrustJWT:     aws.String("your-gateway-trust-jwt"),
    AccessibleSchemaURL: aws.String("https://schema.example.com/v1/schemas/..."),
    AppPrivKeyHex:       aws.String("your-app-private-key-hex"),
    IssuerPrivKeyHex:    aws.String("your-issuer-private-key-hex"),
})
if err != nil {
    log.Fatal(err)
}

ctx := context.Background()

ownerDID := "did:example:owner"
issuerDID := "did:example:issuer"

// Upload a public file
file, _ := os.Open("example.txt")
content, _ := io.ReadAll(file)
output, err := client.PutObject(ctx, &filesdk.PutObjectInput{
    Bucket:     aws.String(ownerDID),
    Key:        aws.String("example.txt"),
    Body:       bytes.NewReader(content),
    AccessType: filesdk.AccessTypePublic,
    IssuerDID:  aws.String(issuerDID),
    ContentType: aws.String("text/plain"),
})

// Download the file
result, err := client.GetObject(ctx, &filesdk.GetObjectInput{
    Bucket: aws.String(ownerDID),
    Key:    aws.String("bafkreicid..."), // CID from upload
})
defer result.Body.Close()
data, _ := io.ReadAll(result.Body)
```

### Uploading Private (Encrypted) Files

```go
ownerDID := "did:example:owner"
issuerDID := "did:example:issuer"

output, err := client.PutObject(ctx, &filesdk.PutObjectInput{
    Bucket:     aws.String(ownerDID),
    Key:        aws.String("secret.txt"),
    Body:       bytes.NewReader(fileContent),
    AccessType: filesdk.AccessTypePrivate, // Private/encrypted file
    IssuerDID:  aws.String(issuerDID),
    ContentType: aws.String("text/plain"),
    Metadata: map[string]string{
        "Authorization": "your-owner-jwt-token",
    },
})
// output.SSEKMSEncryptionContext contains JSON with CID, Capsule, OwnerVCJWT, etc.
```

### Downloading Private (Encrypted) Files

```go
// Owner downloading their own file
result, err := client.GetObject(ctx, &filesdk.GetObjectInput{
    Bucket: aws.String(ownerDID),
    Key:    aws.String(cid),
    Metadata: map[string]string{
        "Authorization": "owner-jwt-token",
    },
}, filesdk.WithDecryptPrivKeyHex(ownerPrivKeyHex))
defer result.Body.Close()

// Viewer downloading with accessible VC
result, err := client.GetObject(ctx, &filesdk.GetObjectInput{
    Bucket: aws.String(ownerDID),
    Key:    aws.String(cid),
    Metadata: map[string]string{
        "Authorization": "viewer-vp-jwt-token",
    },
}, filesdk.WithDecryptPrivKeyHex(viewerPrivKeyHex))
defer result.Body.Close()

data, err := io.ReadAll(result.Body)
```

## API Reference

### Client

#### `New(cfg Config) (*Client, error)`

Creates a new File SDK client.

**Config:**
- `Endpoint` (*string, required): Gateway endpoint URL (e.g., "http://localhost:8083")
- `Timeout` (time.Duration): HTTP client timeout (default: 30s)
- `DefaultHeaders` (http.Header): Default headers for all requests
- `HTTPClient` (*http.Client): Custom HTTP client (optional)
- `CryptProvider` (crypt.Provider): Custom decryptor provider for private downloads (defaults to built-in PRE provider)
- `AuthClient` (auth.Auth): Custom auth client (optional, defaults to ECDSA provider)
- `DIDResolverURL` (*string, required): DID resolver base URL
- `ApplicationDID` (*string, required): Application DID for creating VP tokens
- `GatewayTrustJWT` (*string, required): Gateway trust JWT for VP token creation
- `AccessibleSchemaURL` (*string, required): Schema URL for owner file credentials
- `AppPrivKeyHex` (*string): Application private key hex for signing VP tokens
- `IssuerPrivKeyHex` (*string): Issuer private key hex for creating owner VC during upload
- `OwnerPrivKeyHex` (*string): Owner private key hex used as default for:
  - Decrypting files when owner downloads their own files (GetObject)
  - Re-encapsulating capsules when owner creates accessible VCs (PostAccessibleVC)

### PutObject

#### `PutObject(ctx context.Context, input *PutObjectInput, opts ...PutObjectOpt) (*PutObjectOutput, error)`

Uploads a file to the gateway.

**PutObjectInput:**
- `Bucket` (*string, required): Owner DID (bucket identifier)
- `Key` (*string, required): Name of the file
- `Body` (io.Reader, required): File content reader
- `Metadata` (map[string]string): Additional metadata (e.g., "Authorization" header)
- `AccessType` (AccessType): `AccessTypePublic` or `AccessTypePrivate` (default: AccessTypePublic)
- `ContentType` (*string): MIME type of the file (default: "application/octet-stream")
- `IssuerDID` (*string, required): Issuer DID stored alongside the object

**PutObjectOpt Options:**
- `WithEncryptorChunkSize(chunkSize int)`: Set chunk size for PRE encryption (default: 1MB)
- `WithIssuerPrivKeyHex(privKeyHex string)`: Override issuer private key for creating owner VC
- `WithUploadApplicationPrivKeyHex(privKeyHex string)`: Set application private key for VP token signing

**Returns:**
- `*PutObjectOutput`: Contains `SSEKMSEncryptionContext` (JSON string with CID, Capsule, OwnerVCJWT, etc.)

### GetObject

#### `GetObject(ctx context.Context, input *GetObjectInput, opts ...GetObjectOpt) (*GetObjectOutput, error)`

Downloads a file from the gateway.

**GetObjectInput:**
- `Bucket` (*string, required): Owner DID that was used during upload
- `Key` (*string, required): CID of the file
- `Metadata` (map[string]string): Additional metadata (e.g., "Authorization" header with JWT token)

**GetObjectOpt Options:**
- `WithDecryptPrivKeyHex(privKeyHex string)`: Private key for decrypting private files
  - If not provided, uses `OwnerPrivKeyHex` from config (for owner downloads)
  - Required for viewer downloads (use viewer's private key)
- `WithDownloadApplicationPrivKeyHex(privKeyHex string)`: Application private key for VP token signing

**Returns:**
- `*GetObjectOutput`: Contains:
  - `Body` (io.ReadCloser): Decrypted file content stream (must be closed by caller)
  - `Metadata` (map[string]string): Object metadata (CID, size, content-type, etc.)

## Encryption

The SDK uses Proxy Re-Encryption (PRE) for private file encryption. Files encrypted with the owner's public key can be re-encrypted for viewers using accessible VCs.

### Encryption Flow

1. **Upload (Private File)**:
   - File is encrypted with owner's public key (resolved from DID)
   - Capsule is generated and stored with the file
   - Owner VC is created using issuer's private key

2. **Download (Owner)**:
   - Owner uses their private key to decrypt
   - Private key can be set via `WithDecryptPrivKeyHex` or `OwnerPrivKeyHex` config

3. **Download (Viewer)**:
   - Viewer must have an accessible VC (created via `PostAccessibleVC`)
   - Viewer uses their private key via `WithDecryptPrivKeyHex`
   - Gateway re-encrypts using the accessible VC

### Custom Decryption Providers

You can provide a custom `crypt.Provider` when constructing the client to customize decryption behavior:

```go
type CustomProvider struct {
    // Your custom provider implementation
}

func (p *CustomProvider) NewPreDecryptor(ctx context.Context, capsule string, opts ...crypt.ProviderOpt) (*pre.Decryptor, error) {
    // Custom decryption logic
    // Pull keys from secure stores, implement custom re-encryption, etc.
}

client, err := filesdk.New(filesdk.Config{
    Endpoint:      aws.String(gatewayURL),
    CryptProvider: &CustomProvider{},
})
```

## Access Control & Credentials

The SDK uses Verifiable Credentials (VCs) and Verifiable Presentations (VPs) for access control.

### Owner VC

When a file is uploaded, an Owner VC is automatically created that proves:
- The issuer granted the owner access to the file
- The file CID and capsule information

### Accessible VC

To grant a viewer access to a private file, create an Accessible VC:

```go
accessibleVCJWT, err := client.PostAccessibleVC(ctx, &filesdk.PostAccessibleVCInput{
    OwnerDID:  aws.String(ownerDID),
    ViewerDID: aws.String(viewerDID),
    CID:       aws.String(fileCID),
    Capsule:   aws.String(capsuleHex),
}, filesdk.WithOwnerPrivKeyHex(ownerPrivKeyHex))
```

The viewer can then use this VC in a VP token to download the file.

### Public Key Resolution

Public keys are automatically resolved from DIDs using the configured `DIDResolverURL`. The SDK resolves the verification method `<ownerDID>#key-1` to get the public key for encryption.

## Examples

See the `examples/` directory for complete working examples:

- **Upload**: Uploading public and private files
- **Create Accessible VC**: Granting viewer access to private files
- **Download**: Downloading files as owner or viewer

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
- DID resolver endpoint for resolving public keys
- Application DID and gateway trust JWT for VP token creation
