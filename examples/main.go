package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	filesdk "github.com/dinhwe2612/file-sdk"
	"github.com/dinhwe2612/file-sdk/pkg/crypt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pilacorp/nda-auth-sdk/auth"
	"github.com/pilacorp/nda-auth-sdk/provider"
)

var (
	issuerDID           = "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"
	issuerPrivateKeyHex = "ed9b1db01a02b9779f9631ad591c47d14dc4358649fd76f09fbc97c77a320d4f"
	ownerDID            = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
	ownerPrivateKeyHex  = "c91fdc404bf67d3b3c5f8961bd20273d4498bd27c1675acaf3515ab305ea2786"
	applicationDID      = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
	gatewayTrustJWT     = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwI2tleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjE3NjM1NTU3MDUsImlhdCI6MTc2MzU1NTcwNSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MTZjNTEzMGRlZjY0OTZmNWRlOTNmOTA3NmE1Y2ViMDVjZTU5ZTRiMCIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDplNzRiZTZlYS03ZTBmLTRlN2EtOTI5OS03OGJmYjFlOWMzMzMiLCJuYmYiOjE3NjM1NTU3MDUsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDE2YzUxMzBkZWY2NDk2ZjVkZTkzZjkwNzZhNWNlYjA1Y2U1OWU0YjAiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2F1dGgtZGV2LnBpbGEudm4vYXBpL3YxL3NjaGVtYXMvZTBiNzU3MjQtNmE2Yi00NzdkLWExNWYtMTZhOTJmY2RmYmU4IiwidHlwZSI6Ikpzb25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwIiwicGVybWlzc2lvbnMiOlsiKiJdLCJyZXNvdXJjZSI6ImRpZDpuZGE6dGVzdG5ldDoweDE2YzUxMzBkZWY2NDk2ZjVkZTkzZjkwNzZhNWNlYjA1Y2U1OWU0YjAifSwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6ZTc0YmU2ZWEtN2UwZi00ZTdhLTkyOTktNzhiZmIxZTljMzMzIiwiaXNzdWVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MTZjNTEzMGRlZjY0OTZmNWRlOTNmOTA3NmE1Y2ViMDVjZTU5ZTRiMCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBdXRob3JpemF0aW9uQ3JlZGVudGlhbCJdLCJ2YWxpZEZyb20iOiIyMDI1LTExLTE5VDEyOjM1OjA1WiIsInZhbGlkVW50aWwiOiIyMDI1LTExLTE5VDEyOjM1OjA1WiJ9fQ.8ZgKaQ9d2_l6AxwW-JUeu_sozr8JnynAJO1zXGAsHigPDSgNOmd_xIEaNIMYosVQszoI6NJrYnXyGgGIWek0sg"
	accessibleSchemaURL = "https://auth-dev.pila.vn/api/v1/schemas/dc7ad05d-60d9-427d-a125-a8e09ce9bb1e"
	pilaAuthURL         = "https://auth-dev.pila.vn"
)

type customProvider struct{}

func (p *customProvider) Sign(ctx context.Context, payload []byte, opts ...provider.SignOption) ([]byte, error) {
	options := &provider.SignOptions{}
	for _, opt := range opts {
		opt(options)
	}

	privateKey, err := crypto.ToECDSA(options.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct private key from retrieved hex: %w", err)
	}

	sig, err := crypto.Sign(payload, privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return sig[:64], nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "download":
			runDownload()
		case "create-vc":
			runCreateAccessibleVC()
		default:
			runUpload()
		}
	} else {
		runUpload()
	}
}

// ============================================================================
// PART 1: UPLOAD
// Run: go run examples/main.go
// ============================================================================
func runUpload() {
	ctx := context.Background()

	// Create a client pointing to the gateway domain
	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	applicationPrivateKeyBytes, err := hex.DecodeString(ownerPrivateKeyHex)
	if err != nil {
		log.Fatalf("decode application private key: %v", err)
	}
	issuerPrivateKeyBytes, err := hex.DecodeString(issuerPrivateKeyHex)
	if err != nil {
		log.Fatalf("decode issuer private key: %v", err)
	}

	customProvider := &customProvider{}

	authClient := auth.NewAuth(customProvider, resolverURL)
	client, err := filesdk.New(filesdk.Config{
		Endpoint:            gatewayURL,
		Timeout:             30 * time.Second,
		DIDResolverURL:      resolverURL,
		AuthClient:          authClient,
		ApplicationDID:      applicationDID,
		GatewayTrustJWT:     gatewayTrustJWT,
		AccessibleSchemaURL: accessibleSchemaURL,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	// Load file content to upload
	filePath := "examples/go.mod"
	content, err := os.ReadFile(filePath)
	if err != nil {
		filePath = "go.mod"
		content, err = os.ReadFile(filePath)
		if err != nil {
			log.Fatalf("read file for upload: %v", err)
		}
	}
	objectName := filepath.Base(filePath)

	// Upload the file
	fmt.Println("=== Uploading file ===")
	ownerJWT := "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwianRpIjoiZGlkOm5kYTp0ZXN0bmV0OmFmMTMxMTBlLTFhMWMtNGRkYi1hNDI0LTM5MWY3MjVlNWY0NiIsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaG9sZGVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MmFmN2U4ZWJmZWMxNGY1ZTM5NDY5ZDJjZTg0NDJhNWVlZjlmM2ZhNCIsImlkIjoiZGlkOm5kYTp0ZXN0bmV0OmFmMTMxMTBlLTFhMWMtNGRkYi1hNDI0LTM5MWY3MjVlNWY0NiIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3hObU0xTVRNd1pHVm1OalE1Tm1ZMVpHVTVNMlk1TURjMllUVmpaV0l3TldObE5UbGxOR0l3STJ0bGVTMHhJaXdpZEhsd0lqb2lTbGRVSW4wLmV5SmxlSEFpT2pFM05qTTFOVFUzTURVc0ltbGhkQ0k2TVRjMk16VTFOVGN3TlN3aWFYTnpJam9pWkdsa09tNWtZVHAwWlhOMGJtVjBPakI0TVRaak5URXpNR1JsWmpZME9UWm1OV1JsT1RObU9UQTNObUUxWTJWaU1EVmpaVFU1WlRSaU1DSXNJbXAwYVNJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERwbE56UmlaVFpsWVMwM1pUQm1MVFJsTjJFdE9USTVPUzAzT0dKbVlqRmxPV016TXpNaUxDSnVZbVlpT2pFM05qTTFOVFUzTURVc0luTjFZaUk2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VFkyaGxiV0VpT25zaWFXUWlPaUpvZEhSd2N6b3ZMMkYxZEdndFpHVjJMbkJwYkdFdWRtNHZZWEJwTDNZeEwzTmphR1Z0WVhNdlpUQmlOelUzTWpRdE5tRTJZaTAwTnpka0xXRXhOV1l0TVRaaE9USm1ZMlJtWW1VNElpd2lkSGx3WlNJNklrcHpiMjVUWTJobGJXRWlmU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2ljR1Z5YldsemMybHZibk1pT2xzaUtpSmRMQ0p5WlhOdmRYSmpaU0k2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlmU3dpYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNlpUYzBZbVUyWldFdE4yVXdaaTAwWlRkaExUa3lPVGt0TnpoaVptSXhaVGxqTXpNeklpd2lhWE56ZFdWeUlqb2laR2xrT201a1lUcDBaWE4wYm1WME9qQjRNVFpqTlRFek1HUmxaalkwT1RabU5XUmxPVE5tT1RBM05tRTFZMlZpTURWalpUVTVaVFJpTUNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pCZFhSb2IzSnBlbUYwYVc5dVEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSXNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSjlmUS44WmdLYVE5ZDJfbDZBeHdXLUpVZXVfc296cjhKbnluQUpPMXpYR0FzSGlnUERTZ05PbWRfeElFYU5JTVlvc1ZRc3pvSTZOSnJZblh5R2dHSVdlazBzZyJdfX0.IRVNa0qkxwUqIRJSMDZkx3IZ-n7P6skPtwByYzEoCJc8YyjtxIiF1kNalO4w6bROFMRezuYyMae-a9BbofgHMQ"
	uploadInfo, err := upload(ctx, client, issuerDID, ownerDID, objectName, filePath, ownerJWT, content, applicationPrivateKeyBytes, issuerPrivateKeyBytes)
	if err != nil {
		log.Fatalf("upload failed: %v", err)
	}

	fmt.Println("\n=== Upload successful ===")
	fmt.Printf("CID: %s\n", uploadInfo.CID)
	fmt.Printf("Capsule: %s\n", uploadInfo.Capsule)
	fmt.Printf("OwnerVCJWT: %s\n", uploadInfo.OwnerVCJWT)
	fmt.Println("\nTo create accessible VC, run: go run examples/main.go create-vc")
	fmt.Println("To download, run: go run examples/main.go download")
}

// ============================================================================
// PART 2: CREATE ACCESSIBLE VC
// Run: go run examples/main.go create-vc
// Update the CID and capsule below before running
// ============================================================================
func runCreateAccessibleVC() {
	ctx := context.Background()

	// TODO: Update these values after running upload
	const cid = "bafkreihxejgfxlhheh3bdyfaw24guxmigyycnualgd4ayjymliksqpxthy"                                                                                                                                                                                                                                                                                                                            // Replace with CID from upload
	const capsule = "200000004a21b496448279fec1a39c59fac7c50770848fe4a6f29dff907f1f958291795e2000000016f74fae5306e8751bf4ac7f5f5e1aa9fb58bec26223c6236ddef61e77aa0a08200000001a5825010d2dd87f4f884bd08dd4b42dc37a8b8d483b3c51853cb52235dc445020000000e441abe487bf786ebe5bf2a88cfe8ba53078ed91b60b0f58b0b4a39e6e69fb41200000005b7e8ad2bd60631531a877e367036ccac371e4472fca9de96d2db3be80db729e0000100000" // Replace with capsule from upload
	viewerDID := issuerDID                                                                                                                                                                                                                                                                                                                                                                               // The DID of the person who will view the file

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	customProvider := &customProvider{}

	authClient := auth.NewAuth(customProvider, resolverURL)
	client, err := filesdk.New(filesdk.Config{
		Endpoint:            gatewayURL,
		Timeout:             30 * time.Second,
		DIDResolverURL:      resolverURL,
		AuthClient:          authClient,
		ApplicationDID:      applicationDID,
		GatewayTrustJWT:     gatewayTrustJWT,
		AccessibleSchemaURL: accessibleSchemaURL,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Creating Accessible VC ===")
	accessibleVCJWT, err := client.PostAccessibleVC(ctx, filesdk.GetAccessibleVCRequest{
		OwnerDID:            ownerDID,
		ViewerDID:           viewerDID,
		CID:                 cid,
		Capsule:             capsule,
		AccessibleSchemaURL: accessibleSchemaURL,
		PrivKeyHex:          ownerPrivateKeyHex,
	})
	if err != nil {
		log.Fatalf("create accessible VC failed: %v", err)
	}

	fmt.Println("\n=== Accessible VC created successfully ===")
	fmt.Printf("AccessibleVCJWT: %s\n", accessibleVCJWT)
	fmt.Println("\nTo download, run: go run examples/main.go download")
}

// ============================================================================
// PART 3: DOWNLOAD
// Run: go run examples/main.go download
// Update the CID and accessibleVCJWT below before running
// ============================================================================
func runDownload() {
	ctx := context.Background()

	// TODO: Update these values after running upload
	const cid = "bafkreihxejgfxlhheh3bdyfaw24guxmigyycnualgd4ayjymliksqpxthy" // Replace with CID from upload
	const viewerVPJWT = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwianRpIjoiZGlkOm5kYTp0ZXN0bmV0OjQ5MjUyMzQ3LTJiMmEtNDZiNS1iYzc5LTFlZjE4YzI3OThkNCIsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaG9sZGVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MmFmN2U4ZWJmZWMxNGY1ZTM5NDY5ZDJjZTg0NDJhNWVlZjlmM2ZhNCIsImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjQ5MjUyMzQ3LTJiMmEtNDZiNS1iYzc5LTFlZjE4YzI3OThkNCIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3lZV1kzWlRobFltWmxZekUwWmpWbE16azBOamxrTW1ObE9EUTBNbUUxWldWbU9XWXpabUUwSTJ0bGVTMHhJaXdpZEhsd0lqb2lTbGRVSW4wLmV5SmxlSEFpT2pFM05qTTFOVFUzTURVc0ltbGhkQ0k2TVRjMk16VTFOVGN3TlN3aWFYTnpJam9pWkdsa09tNWtZVHAwWlhOMGJtVjBPakI0TW1GbU4yVTRaV0ptWldNeE5HWTFaVE01TkRZNVpESmpaVGcwTkRKaE5XVmxaamxtTTJaaE5DSXNJbXAwYVNJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvNVlqVTFOMkl3WVMwelpUaGpMVFJoTmpjdFlXWTROeTA1TldKbE9HRmhPVEF4TVRZaUxDSnVZbVlpT2pFM05qTTFOVFUzTURVc0luTjFZaUk2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VFkyaGxiV0VpT25zaWFXUWlPaUpvZEhSd2N6b3ZMMkYxZEdndFpHVjJMbkJwYkdFdWRtNHZZWEJwTDNZeEwzTmphR1Z0WVhNdlpUQmlOelUzTWpRdE5tRTJZaTAwTnpka0xXRXhOV1l0TVRaaE9USm1ZMlJtWW1VNElpd2lkSGx3WlNJNklrcHpiMjVUWTJobGJXRWlmU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2ljR1Z5YldsemMybHZibk1pT2xzaUtpSmRMQ0p5WlhOdmRYSmpaU0k2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlmU3dpYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk9XSTFOVGRpTUdFdE0yVTRZeTAwWVRZM0xXRm1PRGN0T1RWaVpUaGhZVGt3TVRFMklpd2lhWE56ZFdWeUlqb2laR2xrT201a1lUcDBaWE4wYm1WME9qQjRNbUZtTjJVNFpXSm1aV014TkdZMVpUTTVORFk1WkRKalpUZzBOREpoTldWbFpqbG1NMlpoTkNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pCZFhSb2IzSnBlbUYwYVc5dVEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSXNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSjlmUS51YVRKQlloRVhPV1ZEUmx5d0Y0Qm1QUnZna0xYMFRRZU9ndDBxNVdGOEZkSC1Xc19lM3ZQTU9rLWp2V0FHbTB0My0xbXlOVUNzMV9TTEtYdTY4a0tSdyIsImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0kydGxlUzB4SWl3aWRIbHdJam9pU2xkVUluMC5leUpwWVhRaU9qRTNOalF3TlRNMU1ETXNJbWx6Y3lJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvd2VERTJZelV4TXpCa1pXWTJORGsyWmpWa1pUa3paamt3TnpaaE5XTmxZakExWTJVMU9XVTBZakFpTENKdVltWWlPakUzTmpRd05UTTFNRE1zSW5OMVlpSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREb3dlREpoWmpkbE9HVmlabVZqTVRSbU5XVXpPVFEyT1dReVkyVTRORFF5WVRWbFpXWTVaak5tWVRRaUxDSjJZeUk2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlYU3dpWTNKbFpHVnVkR2xoYkZOamFHVnRZU0k2ZXlKcFpDSTZJbWgwZEhCek9pOHZZWFYwYUMxa1pYWXVjR2xzWVM1MmJpOWhjR2t2ZGpFdmMyTm9aVzFoY3k5a1l6ZGhaREExWkMwMk1HUTVMVFF5TjJRdFlURXlOUzFoT0dVd09XTmxPV0ppTVdVaUxDSjBlWEJsSWpvaVNuTnZibE5qYUdWdFlTSjlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKallYQnpkV3hsSWpvaU1qQXdNREF3TURCaU5EVmlNR1EwTVdNNFpURmxOVGxpTldSaVlUTXlaRFJtTVdOalltSTFPRGRrTm1Wak1EVXdZMkpoTmpZME1qTTFaak5pT0RCa01EbGlabVV6TkRVeU1qQXdNREF3TURBd05EQTNPV0UwT0dRMFlXUXdNVGMwTWpGaFlUZzNPR05pWm1RMFpUY3dNamxpTlRFd01tRTRNalV4TldOak5XSTBNak0yWXpCaFpqWTFObUZrWlRnME1qQXdNREF3TURCbFlXTmtZelF4WWpNeFlUZzNaREJqT1RSbE5UZGtPV1poWVRKaE0yUmtZbVZsTm1aak16RTBaR1V5TXpZM1pHSmpZemhpT0RjM09XVTBZakl3WVdJek1qQXdNREF3TURCbU0yVXdaV1V5WVROa04yRmlaamsyT1RKbVpqYzRZV0V3TVRZMU1UUmhNemczWVRFM05qaGxaRGs0TVdZd09UUXdOV1kzTm1JM016ZzJNMlJsTXpKbE1qQXdNREF3TURBMVlqZGxPR0ZrTW1Ka05qQTJNekUxTXpGaE9EYzNaVE0yTnpBek5tTmpZV016TnpGbE5EUTNNbVpqWVRsa1pUazJaREprWWpOaVpUZ3daR0kzTWpsbE1EQXdNREV3TURBd01EQTBaV0l6WmprME5tUmhORGMwTlRaaU16aGtZVEZsWmpGbU9UZ3hOR0UxWWpoaE5EUmhZemcwTVRaa05ERmxOVFE1TUdRMU5UTXpZV00xWldVNFl6Um1OVFkwWVRSaFpEVTFNRFJqWmpOak5HUmxNakprTlRKa1ltVmlaak5oTVRVNU1EVmtPVFpsTlRZNU9XTXpOMkV6WkdVMVpHRTBOemMwWWpCaFlqWXhNVElpTENKamFXUWlPaUppWVdacmNtVnBhSGhsYW1kbWVHeG9hR1ZvTTJKa2VXWmhkekkwWjNWNGJXbG5lWGxqYm5WaGJHZGtOR0Y1YW5sdGJHbHJjM0Z3ZUhSb2VTSXNJbWxrSWpvaVpHbGtPbTVrWVRwMFpYTjBibVYwT2pCNE1tRm1OMlU0WldKbVpXTXhOR1kxWlRNNU5EWTVaREpqWlRnME5ESmhOV1ZsWmpsbU0yWmhOQ0lzSW5CbGNtMXBjM05wYjI1eklqcGJJbkpsWVdRaVhTd2ljbTlzWlNJNkluWnBaWGRsY2lKOUxDSnBjM04xWlhJaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3hObU0xTVRNd1pHVm1OalE1Tm1ZMVpHVTVNMlk1TURjMllUVmpaV0l3TldObE5UbGxOR0l3SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJa1J2WTNWdFpXNTBRV05qWlhOelEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRJMVZERXpPalV4T2pRekt6QTNPakF3SW4xOS5abTNaWE5ER2FOZVg4UjVGUGZ2RUFmekxySlRRMkdpVjc1MldOTjl5TEo4OWRhTDExWnoyN3VNR2ZHeDVfb2M4MXFlZzRERUVXX2hCdktZcFpPUmhxQSJdfX0.ibF3njKBHzt2j2KzDsHcRdEE0OoE1APNl-nEc-Nx9e87vQfi8ubXcMX9QnYEPI54hbpif-gFJ4kJYuYx9lknUg"

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	customProvider := &customProvider{}

	authClient := auth.NewAuth(customProvider, resolverURL)
	client, err := filesdk.New(filesdk.Config{
		Endpoint:            gatewayURL,
		Timeout:             30 * time.Second,
		DIDResolverURL:      resolverURL,
		AuthClient:          authClient,
		ApplicationDID:      applicationDID,
		GatewayTrustJWT:     gatewayTrustJWT,
		AccessibleSchemaURL: accessibleSchemaURL,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Downloading file ===")
	if err := download(ctx, client, ownerDID, cid, viewerVPJWT); err != nil {
		log.Fatalf("download failed: %v", err)
	}

	fmt.Println("\n=== Download completed successfully ===")
}

func upload(ctx context.Context, client *filesdk.Client, issuerDID, ownerDID, objectName, filePath, ownerJWT string, content []byte, applicationPrivateKeyBytes, issuerPrivateKeyBytes []byte) (filesdk.UploadInfo, error) {
	fmt.Printf("Uploading %q to gateway…\n", filePath)
	headers := http.Header{}
	headers.Set("Authorization", ownerJWT)
	uploadInfo, err := client.PutObject(ctx, ownerDID, objectName, bytes.NewReader(content), int64(len(content)),
		filesdk.WithAccessType(filesdk.AccessTypePrivate),
		filesdk.WithContentType("text/plain"),
		filesdk.WithIssuerDID(issuerDID),
		filesdk.WithHeaders(headers),
		filesdk.WithAccessibleSchemaURL(accessibleSchemaURL),
		filesdk.WithPrivKeyHex(issuerPrivateKeyHex), // for creating owner vc
		filesdk.WithPutApplicationSigners(
			provider.WithPrivateKey(applicationPrivateKeyBytes),
		),
	)
	if err != nil {
		return filesdk.UploadInfo{}, fmt.Errorf("upload object: %w", err)
	}

	fmt.Println("uploadInfo", uploadInfo)

	return uploadInfo, nil
}

func download(ctx context.Context, client *filesdk.Client, ownerDID, cid, viewerJWT string) error {
	if viewerJWT == "" {
		return fmt.Errorf("missing viewer JWT for Authorization header")
	}

	headers := http.Header{}
	headers.Set("Authorization", viewerJWT)

	ownerPrivateKeyBytes, err := hex.DecodeString(ownerPrivateKeyHex)
	if err != nil {
		log.Fatalf("decode owner private key: %v", err)
	}

	fmt.Println("Fetching object back from gateway…")
	result, err := client.GetObject(ctx, ownerDID, cid,
		filesdk.WithGetHeaders(headers),
		filesdk.WithDecryptionProviderOptions(
			crypt.WithPrivateKeyHex(issuerPrivateKeyHex),
		),
		filesdk.WithGetApplicationSigners(
			provider.WithPrivateKey(ownerPrivateKeyBytes),
		),
	)
	if err != nil {
		return fmt.Errorf("get object: %w", err)
	}
	defer result.Body.Close()

	info := result.Info
	fmt.Printf("Object Info:\n")
	fmt.Printf("  CID: %s\n", info.CID)
	fmt.Printf("  Content-Type: %s\n", info.ContentType)
	fmt.Printf("  Size: %d bytes\n", info.Size)

	// 3. Stream the file content.
	var total int
	buf := make([]byte, 1024)
	for {
		n, err := result.Body.Read(buf)
		if n > 0 {
			total += n
			fmt.Printf("Read chunk (%d bytes): %s\n", n, string(buf[:n]))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read object: %w", err)
		}
	}

	fmt.Printf("Total bytes read: %d\n", total)
	return nil
}
