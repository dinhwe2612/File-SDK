package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	filesdk "github.com/dinhwe2612/file-sdk"
)

var (
	issuerDID           = "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"
	issuerPrivateKeyHex = "ed9b1db01a02b9779f9631ad591c47d14dc4358649fd76f09fbc97c77a320d4f"
	ownerDID            = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
	ownerPrivateKeyHex  = "c91fdc404bf67d3b3c5f8961bd20273d4498bd27c1675acaf3515ab305ea2786"
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

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            gatewayURL,
		Timeout:             30 * time.Second,
		DIDResolverURL:      resolverURL,
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
	fmt.Printf("Uploading %q to gateway…\n", filePath)

	headers := http.Header{}
	headers.Set("Authorization", ownerJWT)
	uploadInfo, err := client.PutObject(ctx, ownerDID, objectName, bytes.NewReader(content),
		filesdk.WithUploadHeaders(headers),
		filesdk.WithUploadApplicationPrivateKeyHex(ownerPrivateKeyHex),
		filesdk.WithAccessType(filesdk.AccessTypePrivate),
		filesdk.WithContentType("text/plain"),
		filesdk.WithIssuerDID(issuerDID),
		filesdk.WithIssuerPrivateKeyHex(issuerPrivateKeyHex), // for creating owner vc
	)
	if err != nil {
		// log the error
		slog.ErrorContext(ctx, "Failed to upload", "err", err.Error())
		return
	}

	fmt.Println("uploadInfo", uploadInfo)

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
	const cid = "bafkreicjayaqf3iipaf2klddo34gatewiokkuxi66wggbnelmphsj57544"                                                                                                                                                                                                                                                                                                                            // Replace with CID from upload
	const capsule = "20000000c6c3fe1a226a332ccbc12e214919139fb9313d132a2f8a41c1ee45be40afce002000000090d08cfcc1671b831169ec09d60948c92bb9348eb13cb0f6848989dd4356645b20000000b96fb94e9ed8995cfe3d1b68d2b9243a32d4b72d465b05af2534b9742dbe68f7200000007ee4befad0f342923accc240a91984f540f4bc3fbb7edcb4a64a38ba12f9ed612000000036f981a8cf43113400fbc9a31629db6359d0ecf036fdd32f2c75be515a4e55b10000100000" // Replace with capsule from upload
	viewerDID := issuerDID                                                                                                                                                                                                                                                                                                                                                                               // The DID of the person who will view the file

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            gatewayURL,
		Timeout:             30 * time.Second,
		DIDResolverURL:      resolverURL,
		ApplicationDID:      applicationDID,
		GatewayTrustJWT:     gatewayTrustJWT,
		AccessibleSchemaURL: accessibleSchemaURL,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Creating Accessible VC ===")
	accessibleVCJWT, err := client.PostAccessibleVC(ctx, ownerDID, viewerDID, cid, capsule,
		filesdk.WithAccessibleSchemaURL(accessibleSchemaURL),
		filesdk.WithOwnerPrivateKeyHex(ownerPrivateKeyHex),
	)
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
	const cid = "bafkreicjayaqf3iipaf2klddo34gatewiokkuxi66wggbnelmphsj57544" // Replace with CID from upload
	const viewerVPJWT = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwianRpIjoiZGlkOm5kYTp0ZXN0bmV0OmI5OTBkNGViLTliZjAtNGJiYi1iYzY1LWY5NWRlODBmOWFiZCIsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaG9sZGVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MmFmN2U4ZWJmZWMxNGY1ZTM5NDY5ZDJjZTg0NDJhNWVlZjlmM2ZhNCIsImlkIjoiZGlkOm5kYTp0ZXN0bmV0OmI5OTBkNGViLTliZjAtNGJiYi1iYzY1LWY5NWRlODBmOWFiZCIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3lZV1kzWlRobFltWmxZekUwWmpWbE16azBOamxrTW1ObE9EUTBNbUUxWldWbU9XWXpabUUwSTJ0bGVTMHhJaXdpZEhsd0lqb2lTbGRVSW4wLmV5SmxlSEFpT2pFM05qTTFOVFUzTURVc0ltbGhkQ0k2TVRjMk16VTFOVGN3TlN3aWFYTnpJam9pWkdsa09tNWtZVHAwWlhOMGJtVjBPakI0TW1GbU4yVTRaV0ptWldNeE5HWTFaVE01TkRZNVpESmpaVGcwTkRKaE5XVmxaamxtTTJaaE5DSXNJbXAwYVNJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvNVlqVTFOMkl3WVMwelpUaGpMVFJoTmpjdFlXWTROeTA1TldKbE9HRmhPVEF4TVRZaUxDSnVZbVlpT2pFM05qTTFOVFUzTURVc0luTjFZaUk2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VFkyaGxiV0VpT25zaWFXUWlPaUpvZEhSd2N6b3ZMMkYxZEdndFpHVjJMbkJwYkdFdWRtNHZZWEJwTDNZeEwzTmphR1Z0WVhNdlpUQmlOelUzTWpRdE5tRTJZaTAwTnpka0xXRXhOV1l0TVRaaE9USm1ZMlJtWW1VNElpd2lkSGx3WlNJNklrcHpiMjVUWTJobGJXRWlmU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2ljR1Z5YldsemMybHZibk1pT2xzaUtpSmRMQ0p5WlhOdmRYSmpaU0k2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlmU3dpYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk9XSTFOVGRpTUdFdE0yVTRZeTAwWVRZM0xXRm1PRGN0T1RWaVpUaGhZVGt3TVRFMklpd2lhWE56ZFdWeUlqb2laR2xrT201a1lUcDBaWE4wYm1WME9qQjRNbUZtTjJVNFpXSm1aV014TkdZMVpUTTVORFk1WkRKalpUZzBOREpoTldWbFpqbG1NMlpoTkNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pCZFhSb2IzSnBlbUYwYVc5dVEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSXNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSjlmUS51YVRKQlloRVhPV1ZEUmx5d0Y0Qm1QUnZna0xYMFRRZU9ndDBxNVdGOEZkSC1Xc19lM3ZQTU9rLWp2V0FHbTB0My0xbXlOVUNzMV9TTEtYdTY4a0tSdyIsImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0kydGxlUzB4SWl3aWRIbHdJam9pU2xkVUluMC5leUpwWVhRaU9qRTNOalF3TmpRM05UUXNJbWx6Y3lJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvd2VERTJZelV4TXpCa1pXWTJORGsyWmpWa1pUa3paamt3TnpaaE5XTmxZakExWTJVMU9XVTBZakFpTENKdVltWWlPakUzTmpRd05qUTNOVFFzSW5OMVlpSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREb3dlREpoWmpkbE9HVmlabVZqTVRSbU5XVXpPVFEyT1dReVkyVTRORFF5WVRWbFpXWTVaak5tWVRRaUxDSjJZeUk2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlYU3dpWTNKbFpHVnVkR2xoYkZOamFHVnRZU0k2ZXlKcFpDSTZJbWgwZEhCek9pOHZZWFYwYUMxa1pYWXVjR2xzWVM1MmJpOWhjR2t2ZGpFdmMyTm9aVzFoY3k5a1l6ZGhaREExWkMwMk1HUTVMVFF5TjJRdFlURXlOUzFoT0dVd09XTmxPV0ppTVdVaUxDSjBlWEJsSWpvaVNuTnZibE5qYUdWdFlTSjlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKallYQnpkV3hsSWpvaU1qQXdNREF3TURBNVpHUXlOalV6T0RJM05qWmxNbVZsWkRoaFlqUXpaVGRpTlRneU56TTBOalk0TkRVM1lURTFaalF6WXpBM1pUUmpOemN6Tmprd01URm1Nak0xTURZeE1qQXdNREF3TURCak1qYzNaRFZrTmpRelpUWTBZMlEwWXpobFlqVXdPR1psWlRoaVlURTFZalEzTW1NNE1EaGpPRGN3T0RWallXTmhabU01Wm1WbVl6RTNOMlUxTkdWbE1qQXdNREF3TURBMU1qZ3dORGt6WXpnMk9USmhNR1ExTW1WbE9HUTBOVFkzTnpWbFpURmpZVEl4WTJWaVlqa3dNamMxWWpSaU1USm1OREJpT0RnNFpqQTJaamxsWVdOaU1qQXdNREF3TURCaE16TXlOamcyWkdNMVpHRmhaalpsWW1NME5qWmxORFl4TVdVd1l6ZzNNVGMxWkdFek5qYzJNMkl3WTJGbFlUWmlaalUzTkRobE9UWTRNakUwTjJFeE1qQXdNREF3TURBek5tWTVPREZoT0dObU5ETXhNVE0wTURCbVltTTVZVE14TmpJNVpHSTJNelU1WkRCbFkyWXdNelptWkdRek1tWXlZemMxWW1VMU1UVmhOR1UxTldJeE1EQXdNREV3TURBd01EQTBZbU14T1RrME5qSmxOVGd6TWpsak5Ua3lNV001TjJNNU5tRmlOelJpWVRjNU5UbGxZV1F3T1RkaU9ETm1ObUpqTldJMk1UQm1OamsyTnpBeFlUYzRaamd3WmprNU5XWTFNMkkzTUdReU9UVXlNamhoWWpaaE1UVXhOVEpsWm1Zd09EVXdOakl3TnpnME1HUTJPVEk1TnpKaE5HRmlZakJqTlRRek1XTTNPVElpTENKamFXUWlPaUppWVdacmNtVnBZMnBoZVdGeFpqTnBhWEJoWmpKcmJHUmtiek0wWjJGMFpYZHBiMnRyZFhocE5qWjNaMmRpYm1Wc2JYQm9jMm8xTnpVME5DSXNJbWxrSWpvaVpHbGtPbTVrWVRwMFpYTjBibVYwT2pCNE1tRm1OMlU0WldKbVpXTXhOR1kxWlRNNU5EWTVaREpqWlRnME5ESmhOV1ZsWmpsbU0yWmhOQ0lzSW5CbGNtMXBjM05wYjI1eklqcGJJbkpsWVdRaVhTd2ljbTlzWlNJNkluWnBaWGRsY2lKOUxDSnBjM04xWlhJaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3hObU0xTVRNd1pHVm1OalE1Tm1ZMVpHVTVNMlk1TURjMllUVmpaV0l3TldObE5UbGxOR0l3SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJa1J2WTNWdFpXNTBRV05qWlhOelEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRJMVZERTJPalU1T2pFMEt6QTNPakF3SW4xOS50MUFuUGZ6VkxMX0ktS3JLSVdxN29wZHhUYkR6UWc5X3VwYkdmTHN3a1lGSkVSQjd1U3NHQnRndXdBNmFGN3ZGLUpNWWxUUl9SNEVwYTBqT0tfeWNrQSJdfX0.LT720prdKbXa1lGcdBZ_hZgMwLogIe7BYbYLbmmefNdf6NtXkk6kW2iIb4FyYT31zKTOqXdGY74KxZgxk0zhtQ"

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            gatewayURL,
		Timeout:             30 * time.Second,
		DIDResolverURL:      resolverURL,
		ApplicationDID:      applicationDID,
		GatewayTrustJWT:     gatewayTrustJWT,
		AccessibleSchemaURL: accessibleSchemaURL,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Downloading file ===")
	headers := http.Header{}
	headers.Set("Authorization", viewerVPJWT)

	fmt.Println("Fetching object back from gateway…")
	result, err := client.GetObject(ctx, ownerDID, cid,
		filesdk.WithDownloadHeaders(headers),
		filesdk.WithDownloadApplicationPrivateKeyHex(ownerPrivateKeyHex),
		filesdk.WithDecryptPrivateKeyHex(issuerPrivateKeyHex),
	)
	if err != nil {
		slog.Error("get object", "err", err)
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
			slog.Error("Error", "err", err.Error())
		}
	}

	fmt.Printf("Total bytes read: %d\n", total)

	fmt.Println("\n=== Download completed successfully ===")
}
