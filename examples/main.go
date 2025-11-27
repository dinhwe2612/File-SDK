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
	appDID              = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
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
		AppDID:              aws.String(appDID),
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
	const cid = "bafkreidkzn3rjachy7kwn2qfxheqehjkpgzmm4wsdwxpgi4f6xeohyslkq" // Replace with CID from upload
	const vcOwnerJWT = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpYXQiOjE3NjQxNDU2MjEsImlzcyI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJuYmYiOjE3NjQxNDU2MjEsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDE2YzUxMzBkZWY2NDk2ZjVkZTkzZjkwNzZhNWNlYjA1Y2U1OWU0YjAiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXV0aC1kZXYucGlsYS52bi9hcGkvdjEvc2NoZW1hcy9kYzdhZDA1ZC02MGQ5LTQyN2QtYTEyNS1hOGUwOWNlOWJiMWUiLCJ0eXBlIjoiSnNvblNjaGVtYSJ9LCJjcmVkZW50aWFsU3ViamVjdCI6eyJjYXBzdWxlIjoiMjAwMDAwMDBiNTZkNjNjNDU2MjBhMDFhODg0ZTJjYmMzNjUxNWFiNTI4YjY0OWYxNzBkZDEzZWVkZDA2NTk2MjdjMGM2NDFiMjAwMDAwMDBkODJlNDE3NDgzZmI3ZjlkOGRkMGFkMjExMmUwZDIwMzU3NGFmNjY5NDM1Y2Y2NjJlMWNlMzQyYmQ2YzZjY2VjMjAwMDAwMDBhOWQwMjEzNzc4ZDFjYjc5MDUwNzJmMzZjNWU2M2M4MjkxZGUwYmY1ZjMwNjJlN2IwOWJmZmQ4ZmE0MDQ5OTJkMjAwMDAwMDA3MDcyMWFjMTAyY2Q5MWY2MDBmYmIwM2IzMjVhMDRlYjQyMTE4YjhmODg0OTdiYTE4YTgxNDlhM2UyZTNkNWI3MjAwMDAwMDA3ODM0Y2Y0MjkxM2MwMWIzOTE4MzMyN2NmNDRjYmM3MTU1ZTA2ZDRkMDdkYTE3YTdkZGM2MjE4NDVkZDczYmQ2MDAwMDEwMDAwMCIsImNpZCI6ImJhZmtyZWlka3puM3JqYWNoeTdrd24ycWZ4aGVxZWhqa3Bnem1tNHdzZHd4cGdpNGY2eGVvaHlzbGtxIiwiaWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgxNmM1MTMwZGVmNjQ5NmY1ZGU5M2Y5MDc2YTVjZWIwNWNlNTllNGIwIiwicGVybWlzc2lvbnMiOlsiKiJdLCJyb2xlIjoib3duZXJfZmlsZSJ9LCJpc3N1ZXIiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkRvY3VtZW50QWNjZXNzQ3JlZGVudGlhbCJdLCJ2YWxpZEZyb20iOiIyMDI1LTExLTI2VDE1OjI3OjAxKzA3OjAwIn19.arThr5M2IZXl7wM1xYeM87zH7MBd2njkOgc6Y9HJUPo9AEvMLLImdCkITSv8qpOufx6YCquTNTVRtPMWDY534g"
	viewerDID := issuerDID // The DID of the person who will view the file

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	appPrivKeyHex := ownerPrivKeyHex

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            aws.String(gatewayURL),
		Timeout:             30 * time.Second,
		DIDResolverURL:      aws.String(resolverURL),
		AppDID:              aws.String(appDID),
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
			VCOwner:   aws.String(vcOwnerJWT),
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
	const cid = "bafkreidkzn3rjachy7kwn2qfxheqehjkpgzmm4wsdwxpgi4f6xeohyslkq" // Replace with CID from upload
	const viewerVPJWT = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwianRpIjoiZGlkOm5kYTp0ZXN0bmV0OmVmMTFiNGQ1LWJhNWItNDMzNy04ODY3LWJiMjBmMzMwOTlmYiIsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaG9sZGVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MmFmN2U4ZWJmZWMxNGY1ZTM5NDY5ZDJjZTg0NDJhNWVlZjlmM2ZhNCIsImlkIjoiZGlkOm5kYTp0ZXN0bmV0OmVmMTFiNGQ1LWJhNWItNDMzNy04ODY3LWJiMjBmMzMwOTlmYiIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3lZV1kzWlRobFltWmxZekUwWmpWbE16azBOamxrTW1ObE9EUTBNbUUxWldWbU9XWXpabUUwSTJ0bGVTMHhJaXdpZEhsd0lqb2lTbGRVSW4wLmV5SmxlSEFpT2pFM05qTTFOVFUzTURVc0ltbGhkQ0k2TVRjMk16VTFOVGN3TlN3aWFYTnpJam9pWkdsa09tNWtZVHAwWlhOMGJtVjBPakI0TW1GbU4yVTRaV0ptWldNeE5HWTFaVE01TkRZNVpESmpaVGcwTkRKaE5XVmxaamxtTTJaaE5DSXNJbXAwYVNJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERwak1XWTJPV1UwWkMxaU5qY3pMVFJrTWpZdFlqRTFaaTB4TXprNVltVTFZV1kzT1RJaUxDSnVZbVlpT2pFM05qTTFOVFUzTURVc0luTjFZaUk2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VFkyaGxiV0VpT25zaWFXUWlPaUpvZEhSd2N6b3ZMMkYxZEdndFpHVjJMbkJwYkdFdWRtNHZZWEJwTDNZeEwzTmphR1Z0WVhNdlpUQmlOelUzTWpRdE5tRTJZaTAwTnpka0xXRXhOV1l0TVRaaE9USm1ZMlJtWW1VNElpd2lkSGx3WlNJNklrcHpiMjVUWTJobGJXRWlmU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2ljR1Z5YldsemMybHZibk1pT2xzaUtpSmRMQ0p5WlhOdmRYSmpaU0k2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlmU3dpYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNll6Rm1OamxsTkdRdFlqWTNNeTAwWkRJMkxXSXhOV1l0TVRNNU9XSmxOV0ZtTnpreUlpd2lhWE56ZFdWeUlqb2laR2xrT201a1lUcDBaWE4wYm1WME9qQjRNbUZtTjJVNFpXSm1aV014TkdZMVpUTTVORFk1WkRKalpUZzBOREpoTldWbFpqbG1NMlpoTkNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pCZFhSb2IzSnBlbUYwYVc5dVEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSXNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSjlmUS56bXVPQk94RTFKYTNla1M4YjdIT2RoVTRyeExWdEQ1dlV5UGJ3cTNrREtNZGRSeFQzckJMTE8wTkFsSDFYZkZ3VXh6V25QX0xNR1ktUndsTjdQbUZlUSIsImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0kydGxlUzB4SWl3aWRIbHdJam9pU2xkVUluMC5leUpwWVhRaU9qRTNOalF4TkRVM09Ea3NJbWx6Y3lJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvd2VERTJZelV4TXpCa1pXWTJORGsyWmpWa1pUa3paamt3TnpaaE5XTmxZakExWTJVMU9XVTBZakFpTENKdVltWWlPakUzTmpReE5EVTNPRGtzSW5OMVlpSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREb3dlREpoWmpkbE9HVmlabVZqTVRSbU5XVXpPVFEyT1dReVkyVTRORFF5WVRWbFpXWTVaak5tWVRRaUxDSjJZeUk2ZXlKQVkyOXVkR1Y0ZENJNld5Sm9kSFJ3Y3pvdkwzZDNkeTUzTXk1dmNtY3Zibk12WTNKbFpHVnVkR2xoYkhNdmRqSWlYU3dpWTNKbFpHVnVkR2xoYkZOamFHVnRZU0k2ZXlKcFpDSTZJbWgwZEhCek9pOHZZWFYwYUMxa1pYWXVjR2xzWVM1MmJpOWhjR2t2ZGpFdmMyTm9aVzFoY3k5a1l6ZGhaREExWkMwMk1HUTVMVFF5TjJRdFlURXlOUzFoT0dVd09XTmxPV0ppTVdVaUxDSjBlWEJsSWpvaVNuTnZibE5qYUdWdFlTSjlMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKallYQnpkV3hsSWpvaU1qQXdNREF3TURBeU16Y3dORGN3TkRWaE1EZzNNak5sTnpNMk1UQTRabVZoWWpCak9XTmxNVGczWTJabE1ERTRaalV4TVRFeU5qRTNaR1JpTURnME5XTmhZekZoTVdVME1qQXdNREF3TURBMVl6WmlaVGhsTURaaE5UbGhPV1l3TmprNU5XRTJNREExTURFeE1UVXdNbVV3TnpSa016RTBNR1ZrWkRVNE1UY3paRGM0T1dZd1l6ZGhZV0V5TUdJMk1qQXdNREF3TURCaE56aG1aVFUxWlRsaE16aG1OVE00WWpkbVpUWmhPREF4TTJOaVpqSTBORFk1TUdSbE5tVmtOVFExTlRrMU5EaGlZemcxTldNM01URTJNMkl3WWpnNE1qQXdNREF3TURBMVltRmhNREZqT0dWa1pHTmhOakF6TmpJMk5tWTROelppTldFek5qZzBaV1JrTkdVNVpXWTRNREZrWlRRMFpERTFOemt3TXpReFpXTmhabUl5T0dSak1qQXdNREF3TURBM09ETTBZMlkwTWpreE0yTXdNV0l6T1RFNE16TXlOMk5tTkRSalltTTNNVFUxWlRBMlpEUmtNRGRrWVRFM1lUZGtaR00yTWpFNE5EVmtaRGN6WW1RMk1EQXdNREV3TURBd01EQTBaVEU0TXpka1lqVXdaR1F5T0RObE5qRTRaV1JpTWpVMU56WmxaVEF4WXpaaE5EVmtOekZrWldaaFlURTNPRFV5T1dabE16bGlNV1l4T0daaE9USTFZbVk0TWpVMU1tUmhOelppWTJSaU5HWTNOalpsTURNNFpESmtaR000T0RCalltVmpZMkptT0RFM05qWXdNMlF4TVRZelpEWTFPV1pqWmpJeVpXWmlZVGNpTENKamFXUWlPaUppWVdacmNtVnBaR3Q2YmpOeWFtRmphSGszYTNkdU1uRm1lR2hsY1dWb2FtdHdaM3B0YlRSM2MyUjNlSEJuYVRSbU5uaGxiMmg1YzJ4cmNTSXNJbWxrSWpvaVpHbGtPbTVrWVRwMFpYTjBibVYwT2pCNE1tRm1OMlU0WldKbVpXTXhOR1kxWlRNNU5EWTVaREpqWlRnME5ESmhOV1ZsWmpsbU0yWmhOQ0lzSW5CbGNtMXBjM05wYjI1eklqcGJJbkpsWVdRaVhTd2ljbTlzWlNJNkluWnBaWGRsY2lKOUxDSnBjM04xWlhJaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3hObU0xTVRNd1pHVm1OalE1Tm1ZMVpHVTVNMlk1TURjMllUVmpaV0l3TldObE5UbGxOR0l3SWl3aWRIbHdaU0k2V3lKV1pYSnBabWxoWW14bFEzSmxaR1Z1ZEdsaGJDSXNJa1J2WTNWdFpXNTBRV05qWlhOelEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRJMlZERTFPakk1T2pRNUt6QTNPakF3SW4xOS4tQm1GUk4xUGRFTzRQS25GNWdmNjFWbGZaSjFwYzR4MnEyRVdKSHhCSFNVNUJ3S0JWdXJOOWdXUFdzSzNuVGlLMFpkOXZIZE1DZVlON1NpOF9lZTFudyJdfX0.lXJoUQaCFmAGVxBsIs821X24-uv7pUNHhGOyhMaJY9xVZUscgO-eGNTC9msdVLXLnHubCUUdRnhB-6r1wc6aRA"

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	appPrivKeyHex := ownerPrivKeyHex
	viewerPrivKeyHex := issuerPrivKeyHex

	client, err := filesdk.New(filesdk.Config{
		Endpoint:            aws.String(gatewayURL),
		Timeout:             30 * time.Second,
		DIDResolverURL:      aws.String(resolverURL),
		AppDID:              aws.String(appDID),
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
