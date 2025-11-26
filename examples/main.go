package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	filesdk "github.com/dinhwe2612/file-sdk"
)

var (
	issuerDID           = "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"
	issuerPrivKeyHex    = "ed9b1db01a02b9779f9631ad591c47d14dc4358649fd76f09fbc97c77a320d4f"
	ownerDID            = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
	ownerPrivKeyHex     = "c91fdc404bf67d3b3c5f8961bd20273d4498bd27c1675acaf3515ab305ea2786"
	applicationDID      = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
	gatewayTrustJWT     = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwI2tleS0xIiwidHlwIjoiSldUIn0.eyJleHAiOjE3NjM1NTU3MDUsImlhdCI6MTc2MzU1NTcwNSwiaXNzIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MTZjNTEzMGRlZjY0OTZmNWRlOTNmOTA3NmE1Y2ViMDVjZTU5ZTRiMCIsImp0aSI6ImRpZDpuZGE6dGVzdG5ldDplNzRiZTZlYS03ZTBmLTRlN2EtOTI5OS03OGJmYjFlOWMzMzMiLCJuYmYiOjE3NjM1NTU3MDUsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDE2YzUxMzBkZWY2NDk2ZjVkZTkzZjkwNzZhNWNlYjA1Y2U1OWU0YjAiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJodHRwczovL2F1dGgtZGV2LnBpbGEudm4vYXBpL3YxL3NjaGVtYXMvZTBiNzU3MjQtNmE2Yi00NzdkLWExNWYtMTZhOTJmY2RmYmU4IiwidHlwZSI6Ikpzb25TY2hlbWEifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwIiwicGVybWlzc2lvbnMiOlsiKiJdLCJyZXNvdXJjZSI6ImRpZDpuZGE6dGVzdG5ldDoweDE2YzUxMzBkZWY2NDk2ZjVkZTkzZjkwNzZhNWNlYjA1Y2U1OWU0YjAifSwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6ZTc0YmU2ZWEtN2UwZi00ZTdhLTkyOTktNzhiZmIxZTljMzMzIiwiaXNzdWVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MTZjNTEzMGRlZjY0OTZmNWRlOTNmOTA3NmE1Y2ViMDVjZTU5ZTRiMCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJBdXRob3JpemF0aW9uQ3JlZGVudGlhbCJdLCJ2YWxpZEZyb20iOiIyMDI1LTExLTE5VDEyOjM1OjA1WiIsInZhbGlkVW50aWwiOiIyMDI1LTExLTE5VDEyOjM1OjA1WiJ9fQ.8ZgKaQ9d2_l6AxwW-JUeu_sozr8JnynAJO1zXGAsHigPDSgNOmd_xIEaNIMYosVQszoI6NJrYnXyGgGIWek0sg"
	accessibleSchemaURL = "https://auth-dev.pila.vn/api/v1/schemas/dc7ad05d-60d9-427d-a125-a8e09ce9bb1e"
)

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

	appPrivKeyHex := ownerPrivKeyHex

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            aws.String(gatewayURL),
		Timeout:             30 * time.Second,
		DIDResolverURL:      aws.String(resolverURL),
		ApplicationDID:      aws.String(applicationDID),
		GatewayTrustJWT:     aws.String(gatewayTrustJWT),
		AccessibleSchemaURL: aws.String(accessibleSchemaURL),
		AppPrivKeyHex:       aws.String(appPrivKeyHex),
		IssuerPrivKeyHex:    aws.String(issuerPrivKeyHex),
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
	fmt.Printf("Uploading %q to gateway…\n", filePath)

	uploadOutput, err := client.PutObject(ctx,
		&filesdk.PutObjectInput{
			Bucket:     aws.String(ownerDID),
			Key:        aws.String(objectName),
			Body:       bytes.NewReader(content),
			AccessType: filesdk.AccessTypePrivate,
			IssuerDID:  aws.String(issuerDID),
			Metadata: map[string]string{
				"Authorization": ownerJWT,
			},
		},
	)
	if err != nil {
		// log the error
		slog.ErrorContext(ctx, "Failed to upload", "err", err.Error())
		return
	}

	// parse the uploadInfo to UploadInfo
	var uploadInfo filesdk.UploadInfo
	err = json.Unmarshal([]byte(*uploadOutput.SSEKMSEncryptionContext), &uploadInfo)
	if err != nil {
		log.Fatalf("parse upload info: %v", err)
	}

	fmt.Println("=== Upload successful ===")
	fmt.Printf("CID: %s\n", uploadInfo.CID)
	fmt.Printf("OwnerDID: %s\n", uploadInfo.OwnerDID)
	fmt.Printf("CreatedAt: %s\n", uploadInfo.CreatedAt)
	fmt.Printf("FileName: %s\n", uploadInfo.FileName)
	fmt.Printf("FileType: %s\n", uploadInfo.FileType)
	fmt.Printf("AccessLevel: %s\n", uploadInfo.AccessLevel)
	fmt.Printf("IssuerDID: %s\n", uploadInfo.IssuerDID)
	fmt.Printf("OwnerVCJWT: %s\n", uploadInfo.OwnerVCJWT)
}

// ============================================================================
// PART 2: CREATE ACCESSIBLE VC
// Run: go run examples/main.go create-vc
// Update the CID and capsule below before running
// ============================================================================
func runCreateAccessibleVC() {
	ctx := context.Background()

	// TODO: Update these values after running upload
	const cid = "bafkreihi3uht7m72ftyqq4rp4agvq2dd3lihkqbu5jh7uqtjnce7jnwgla"                                                                                                                                                                                                                                                                                                                            // Replace with CID from upload
	const capsule = "20000000d41004a9675d6422dd4e8ec5a837ed2e25dcb67b3334ccde56becfe04c41c61820000000def6a0d6b13215758cd9bf4a566635febb8e412947b7b9d65b52aca317cbf47820000000bcdb898cc32199ccfde1c47c0fba680a6be29c4007537a9d1a75b2841c67dea7200000001708e2bed23715659a32849a872f08fe08deb4591f8495ceb230580a0f7f726920000000c5a8968458541ed8398a46799681f076600dc42ea4150c589bb68c0145a893e70000100000" // Replace with capsule from upload
	viewerDID := issuerDID                                                                                                                                                                                                                                                                                                                                                                               // The DID of the person who will view the file

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	appPrivKeyHex := ownerPrivKeyHex

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            aws.String(gatewayURL),
		Timeout:             30 * time.Second,
		DIDResolverURL:      aws.String(resolverURL),
		ApplicationDID:      aws.String(applicationDID),
		GatewayTrustJWT:     aws.String(gatewayTrustJWT),
		AccessibleSchemaURL: aws.String(accessibleSchemaURL),
		AppPrivKeyHex:       aws.String(appPrivKeyHex),
		OwnerPrivKeyHex:     aws.String(ownerPrivKeyHex),
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Creating Accessible VC ===")
	accessibleVCJWT, err := client.PostAccessibleVC(ctx,
		&filesdk.PostAccessibleVCInput{
			OwnerDID:  aws.String(ownerDID),
			ViewerDID: aws.String(viewerDID),
			CID:       aws.String(cid),
			Capsule:   aws.String(capsule),
		},
	)
	if err != nil {
		log.Fatalf("create accessible VC failed: %v", err)
	}

	fmt.Println("\n=== Accessible VC created successfully ===")
	fmt.Printf("AccessibleVCJWT: %s\n", *accessibleVCJWT.VCJWT)
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
	const cid = "bafkreihi3uht7m72ftyqq4rp4agvq2dd3lihkqbu5jh7uqtjnce7jnwgla" // Replace with CID from upload
	const viewerVPJWT = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwianRpIjoiZGlkOm5kYTp0ZXN0bmV0OjgzODY1NDNiLTczYTYtNDg1MC04MTJkLWNhNDU1NmU2YzNlOSIsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaG9sZGVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MmFmN2U4ZWJmZWMxNGY1ZTM5NDY5ZDJjZTg0NDJhNWVlZjlmM2ZhNCIsImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjgzODY1NDNiLTczYTYtNDg1MC04MTJkLWNhNDU1NmU2YzNlOSIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3lZV1kzWlRobFltWmxZekUwWmpWbE16azBOamxrTW1ObE9EUTBNbUUxWldWbU9XWXpabUUwSTJ0bGVTMHhJaXdpZEhsd0lqb2lTbGRVSW4wLmV5SmxlSEFpT2pFM05qTTFOVFUzTURVc0ltbGhkQ0k2TVRjMk16VTFOVGN3TlN3aWFYTnpJam9pWkdsa09tNWtZVHAwWlhOMGJtVjBPakI0TW1GbU4yVTRaV0ptWldNeE5HWTFaVE01TkRZNVpESmpaVGcwTkRKaE5XVmxaamxtTTJaaE5DSXNJbXAwYVNJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvNVlqVTFOMkl3WVMwelpUaGpMVFJoTmpjdFlXWTROeTA1TldKbE9HRmhPVEF4TVRZaUxDSnVZbVlpT2pFM05qTTFOVFUzTURVc0luTjFZaUk2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VFkyaGxiV0VpT25zaWFXUWlPaUpvZEhSd2N6b3ZMMkYxZEdndFpHVjJMbkJwYkdFdWRtNHZZWEJwTDNZeEwzTmphR1Z0WVhNdlpUQmlOelUzTWpRdE5tRTJZaTAwTnpka0xXRXhOV1l0TVRaaE9USm1ZMlJtWW1VNElpd2lkSGx3WlNJNklrcHpiMjVUWTJobGJXRWlmU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2ljR1Z5YldsemMybHZibk1pT2xzaUtpSmRMQ0p5WlhOdmRYSmpaU0k2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlmU3dpYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk9XSTFOVGRpTUdFdE0yVTRZeTAwWVRZM0xXRm1PRGN0T1RWaVpUaGhZVGt3TVRFMklpd2lhWE56ZFdWeUlqb2laR2xrT201a1lUcDBaWE4wYm1WME9qQjRNbUZtTjJVNFpXSm1aV014TkdZMVpUTTVORFk1WkRKalpUZzBOREpoTldWbFpqbG1NMlpoTkNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pCZFhSb2IzSnBlbUYwYVc5dVEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSXNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSjlmUS51YVRKQlloRVhPV1ZEUmx5d0Y0Qm1QUnZna0xYMFRRZU9ndDBxNVdGOEZkSC1Xc19lM3ZQTU9rLWp2V0FHbTB0My0xbXlOVUNzMV9TTEtYdTY4a0tSdyIsImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0kydGxlUzB4SWl3aWRIbHdJam9pU2xkVUluMC5leUpwWVhRaU9qRTNOalF4TXpFeU1qZ3NJbWx6Y3lJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvd2VERTJZelV4TXpCa1pXWTJORGsyWmpWa1pUa3paamt3TnpaaE5XTmxZakExWTJVMU9XVTBZakFpTENKdVltWWlPakUzTmpReE16RXlNamdzSW5OMVlpSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREb3dlREpoWmpkbE9HVmlabVZqTVRSbU5XVXpPVFEyT1dReVkyVTRORFF5WVRWbFpXWTVaak5tWVRRaUxDSjJZeUk2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlYU3dpWTNKbFpHVnVkR2xoYkZOamFHVnRZU0k2ZXlKcFpDSTZJbWgwZEhCek9pOHZZWFYwYUMxa1pYWXVjR2xzWVM1MmJpOWhjR2t2ZGpFdmMyTm9aVzFoY3k5a1l6ZGhaREExWkMwMk1HUTVMVFF5TjJRdFlURXlOUzFoT0dVd09XTmxPV0ppTVdVaUxDSjBlWEJsSWpvaVNuTnZibE5qYUdWdFlTSjlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKallYQnpkV3hsSWpvaU1qQXdNREF3TURCbE5HTXhNREkxWWpoa09HSmxOalZrWkRZeU16UXpObVJsWkRsak5UVXpPR1kyTW1NMVptTXhNVEl3TURWbE5XSTRZVEV4WlRrMFpUUTBOamRsT1dKak1qQXdNREF3TURBNFpHUmhaVEF6Wm1VMU0yUmhZakZqWkdGaU5qWTJNRGMyTkdGaE9ERTJZV1l5WmpJMk5qRmtOelEwWVRJellUWTJZekpoWVdSaU56VTJNalZpTVRJeE1qQXdNREF3TURBMU16ZzVZalF5TjJOalpqVXhPVEJoWkRSbU4yRTJNREl5WkdZeE5tWTRZV0poWlRaaE1ESXlOamN6Tm1Nd05HTTVOREl5TlRjMU5EYzJZMk16TXpZME1qQXdNREF3TURBMFpEQTVaV1EwWkRSa016Rm1NbUkwT0dFME4yTXpOemt6Wm1SaFltTXdOVFpoT1dFME1UUmpZVEV3T0dJeFpEQmxaR1V4WlRSbE0yUXdZak0yWkdVNE1qQXdNREF3TURCak5XRTRPVFk0TkRVNE5UUXhaV1E0TXprNFlUUTJOems1TmpneFpqQTNOall3TUdSak5ESmxZVFF4TlRCak5UZzVZbUkyT0dNd01UUTFZVGc1TTJVM01EQXdNREV3TURBd01EQTBNR1F3TURVMU1UaGpORGMxTWpnNVlqUXlPR0ZrWXprek1tWXhOamMzWlRZMU5qbG1NakZoT0RnNFpEWmxPR1ExTldFeE5HRXhOekpqTXpNelkyUTVOakV4WldJME0yWmlaVE5tWlRkall6aGxaR0ZrTlRabU1UY3dZelEzT1RRMVltRTNPRFF3WkRZNVpUUXlZamhqWmpRNE1USmxPV000Tm1Sak5qazNPR1FpTENKamFXUWlPaUppWVdacmNtVnBhR2t6ZFdoME4yMDNNbVowZVhGeE5ISndOR0ZuZG5FeVpHUXpiR2xvYTNGaWRUVnFhRGQxY1hScWJtTmxOMnB1ZDJkc1lTSXNJbWxrSWpvaVpHbGtPbTVrWVRwMFpYTjBibVYwT2pCNE1tRm1OMlU0WldKbVpXTXhOR1kxWlRNNU5EWTVaREpqWlRnME5ESmhOV1ZsWmpsbU0yWmhOQ0lzSW5CbGNtMXBjM05wYjI1eklqcGJJbkpsWVdRaVhTd2ljbTlzWlNJNkluWnBaWGRsY2lKOUxDSnBjM04xWlhJaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3hObU0xTVRNd1pHVm1OalE1Tm1ZMVpHVTVNMlk1TURjMllUVmpaV0l3TldObE5UbGxOR0l3SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJa1J2WTNWdFpXNTBRV05qWlhOelEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRJMlZERXhPakkzT2pBNEt6QTNPakF3SW4xOS5mMnJlWVRlTVhTZkJ1Y05JWE5TNXQyMEpVOHJ1XzNfYklBUHJ0VGVZcG9jTVVWa1pfcUZjSU1zc0lDZzZMZHlNX1AwUVpLREVNa21ienNRYWkxQXFBZyJdfX0.gxyfJYmt9aj4wmXSa6UL8NHUD5kjkuvW0bz1p6IWqkV867BU_dRFksuQi-V5RFXTGAYouomQIqDRbpm3XfXYIw"

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	appPrivKeyHex := ownerPrivKeyHex
	viewerPrivKeyHex := issuerPrivKeyHex

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            aws.String(gatewayURL),
		Timeout:             30 * time.Second,
		DIDResolverURL:      aws.String(resolverURL),
		ApplicationDID:      aws.String(applicationDID),
		GatewayTrustJWT:     aws.String(gatewayTrustJWT),
		AccessibleSchemaURL: aws.String(accessibleSchemaURL),
		AppPrivKeyHex:       aws.String(appPrivKeyHex),
		ViewerPrivKeyHex:    aws.String(viewerPrivKeyHex),
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Downloading file ===")
	headers := http.Header{}
	headers.Set("Authorization", viewerVPJWT)

	fmt.Println("Fetching object back from gateway…")
	result, err := client.GetObject(ctx,
		&filesdk.GetObjectInput{
			Bucket: aws.String(ownerDID),
			Key:    aws.String(cid),
			Metadata: map[string]string{
				"Authorization": viewerVPJWT,
			},
		},
	)
	if err != nil {
		slog.Error("get object", "err", err)
		return
	}
	defer result.Body.Close()

	metadata := result.Metadata
	fmt.Printf("Object Info:\n")
	fmt.Printf("  CID: %s\n", metadata["cid"])
	fmt.Printf("  Content-Type: %s\n", metadata["content-type"])
	fmt.Printf("  Size: %s bytes\n", metadata["size"])
	for key, value := range metadata {
		fmt.Printf("  %s: %s\n", key, value)
	}

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
			slog.Error("Error reading file", "err", err)
			break // Stop reading on error
		}
	}

	fmt.Printf("Total bytes read: %d\n", total)
	fmt.Println("\n=== Download completed successfully ===")
}
