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
	verificationmethod "github.com/pilacorp/go-credential-sdk/credential/common/verification-method"
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
	accessibleSchemaID  = "dc7ad05d-60d9-427d-a125-a8e09ce9bb1e"
	pilaAuthURL         = "https://auth-dev.pila.vn"
)

type customProvider struct {
	privKeyHex string
}

func (p *customProvider) Sign(ctx context.Context, payload []byte, opts ...provider.SignOption) ([]byte, error) {
	privateKey, err := crypto.HexToECDSA(p.privKeyHex)
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
	filesdk.SetApplicationDID(applicationDID)
	filesdk.SetGatewayTrustJWT(gatewayTrustJWT)

	if len(os.Args) > 1 && os.Args[1] == "download" {
		runDownload()
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

	filesdk.SetApplicationDID(ownerDID)

	// Create a client pointing to the gateway domain
	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	// Create resolver
	resolver := verificationmethod.NewResolver(resolverURL)

	ownerPrivateKeyBytes, err := hex.DecodeString("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		log.Fatalf("decode owner private key: %v", err)
	}
	issuerPrivateKeyBytes, err := hex.DecodeString(issuerPrivateKeyHex)
	if err != nil {
		log.Fatalf("decode issuer private key: %v", err)
	}
	customProvider := &customProvider{
		privKeyHex: ownerPrivateKeyHex,
	}

	authClient := auth.NewAuth(customProvider, resolverURL)
	client, err := filesdk.New(filesdk.Config{
		Endpoint: gatewayURL,
		Timeout:  30 * time.Second,
		Resolver: resolver,
		Auth:     authClient,
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
	cid, err := upload(ctx, client, issuerDID, ownerDID, objectName, filePath, ownerJWT, content, ownerPrivateKeyBytes, issuerPrivateKeyBytes)
	if err != nil {
		log.Fatalf("upload failed: %v", err)
	}

	fmt.Println("\n=== Upload successful ===")
	fmt.Printf("CID: %s\n", cid)
	fmt.Println("\nTo download, run: go run examples/main.go download")
}

// ============================================================================
// PART 2: DOWNLOAD
// Run: go run examples/main.go download
// Update the CID and viewerJWT below before running
// ============================================================================
func runDownload() {
	ctx := context.Background()

	// TODO: Update these values after running upload
	const cid = "bafkreibat2ojeldeu5pyaiymf6nlsh3zlwjhlxvuaare7x3bilgsh5zdey" // Replace with CID from upload
	const viewerJWT = "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0I2tleS0xIiwidHlwIjoiSldUIn0.eyJpc3MiOiJkaWQ6bmRhOnRlc3RuZXQ6MHgyYWY3ZThlYmZlYzE0ZjVlMzk0NjlkMmNlODQ0MmE1ZWVmOWYzZmE0IiwianRpIjoiZGlkOm5kYTp0ZXN0bmV0OjYwM2FjNjg5LWJmNzgtNGI1MC1iYjM1LWQwZTVmMmVhMWUyMSIsInN1YiI6ImRpZDpuZGE6dGVzdG5ldDoweDJhZjdlOGViZmVjMTRmNWUzOTQ2OWQyY2U4NDQyYTVlZWY5ZjNmYTQiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvZXhhbXBsZXMvdjIiXSwiaG9sZGVyIjoiZGlkOm5kYTp0ZXN0bmV0OjB4MmFmN2U4ZWJmZWMxNGY1ZTM5NDY5ZDJjZTg0NDJhNWVlZjlmM2ZhNCIsImlkIjoiZGlkOm5kYTp0ZXN0bmV0OjYwM2FjNjg5LWJmNzgtNGI1MC1iYjM1LWQwZTVmMmVhMWUyMSIsInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5rc2lMQ0pyYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk1IZ3lZV1kzWlRobFltWmxZekUwWmpWbE16azBOamxrTW1ObE9EUTBNbUUxWldWbU9XWXpabUUwSTJ0bGVTMHhJaXdpZEhsd0lqb2lTbGRVSW4wLmV5SmxlSEFpT2pFM05qTTFOVFUzTURVc0ltbGhkQ0k2TVRjMk16VTFOVGN3TlN3aWFYTnpJam9pWkdsa09tNWtZVHAwWlhOMGJtVjBPakI0TW1GbU4yVTRaV0ptWldNeE5HWTFaVE01TkRZNVpESmpaVGcwTkRKaE5XVmxaamxtTTJaaE5DSXNJbXAwYVNJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvNVlqVTFOMkl3WVMwelpUaGpMVFJoTmpjdFlXWTROeTA1TldKbE9HRmhPVEF4TVRZaUxDSnVZbVlpT2pFM05qTTFOVFUzTURVc0luTjFZaUk2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlMQ0oyWXlJNmV5SkFZMjl1ZEdWNGRDSTZXeUpvZEhSd2N6b3ZMM2QzZHk1M015NXZjbWN2TWpBeE9DOWpjbVZrWlc1MGFXRnNjeTkyTVNJc0ltaDBkSEJ6T2k4dmQzZDNMbmN6TG05eVp5OHlNREU0TDJOeVpXUmxiblJwWVd4ekwyVjRZVzF3YkdWekwzWXhJbDBzSW1OeVpXUmxiblJwWVd4VFkyaGxiV0VpT25zaWFXUWlPaUpvZEhSd2N6b3ZMMkYxZEdndFpHVjJMbkJwYkdFdWRtNHZZWEJwTDNZeEwzTmphR1Z0WVhNdlpUQmlOelUzTWpRdE5tRTJZaTAwTnpka0xXRXhOV1l0TVRaaE9USm1ZMlJtWW1VNElpd2lkSGx3WlNJNklrcHpiMjVUWTJobGJXRWlmU3dpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2ljR1Z5YldsemMybHZibk1pT2xzaUtpSmRMQ0p5WlhOdmRYSmpaU0k2SW1ScFpEcHVaR0U2ZEdWemRHNWxkRG93ZURFMll6VXhNekJrWldZMk5EazJaalZrWlRrelpqa3dOelpoTldObFlqQTFZMlUxT1dVMFlqQWlmU3dpYVdRaU9pSmthV1E2Ym1SaE9uUmxjM1J1WlhRNk9XSTFOVGRpTUdFdE0yVTRZeTAwWVRZM0xXRm1PRGN0T1RWaVpUaGhZVGt3TVRFMklpd2lhWE56ZFdWeUlqb2laR2xrT201a1lUcDBaWE4wYm1WME9qQjRNbUZtTjJVNFpXSm1aV014TkdZMVpUTTVORFk1WkRKalpUZzBOREpoTldWbFpqbG1NMlpoTkNJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pCZFhSb2IzSnBlbUYwYVc5dVEzSmxaR1Z1ZEdsaGJDSmRMQ0oyWVd4cFpFWnliMjBpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSXNJblpoYkdsa1ZXNTBhV3dpT2lJeU1ESTFMVEV4TFRFNVZERXlPak0xT2pBMVdpSjlmUS51YVRKQlloRVhPV1ZEUmx5d0Y0Qm1QUnZna0xYMFRRZU9ndDBxNVdGOEZkSC1Xc19lM3ZQTU9rLWp2V0FHbTB0My0xbXlOVUNzMV9TTEtYdTY4a0tSdyIsImV5SmhiR2NpT2lKRlV6STFOa3NpTENKcmFXUWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0kydGxlUzB4SWl3aWRIbHdJam9pU2xkVUluMC5leUpsZUhBaU9qRTNOak0xTlRVM01EVXNJbWxoZENJNk1UYzJNelUxTlRjd05Td2lhWE56SWpvaVpHbGtPbTVrWVRwMFpYTjBibVYwT2pCNE1UWmpOVEV6TUdSbFpqWTBPVFptTldSbE9UTm1PVEEzTm1FMVkyVmlNRFZqWlRVNVpUUmlNQ0lzSW1wMGFTSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREcG1aak16TURBMVlTMDNNVE5oTFRReE5USXRPR1ptWkMwNVpUTXhOR0kwT0ROa1pqUWlMQ0p1WW1ZaU9qRTNOak0xTlRVM01EVXNJbk4xWWlJNkltUnBaRHB1WkdFNmRHVnpkRzVsZERvd2VESmhaamRsT0dWaVptVmpNVFJtTldVek9UUTJPV1F5WTJVNE5EUXlZVFZsWldZNVpqTm1ZVFFpTENKMll5STZleUpBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSXNJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMMlY0WVcxd2JHVnpMM1l4SWwwc0ltTnlaV1JsYm5ScFlXeFRZMmhsYldFaU9uc2lhV1FpT2lKb2RIUndjem92TDJGMWRHZ3RaR1YyTG5CcGJHRXVkbTR2WVhCcEwzWXhMM05qYUdWdFlYTXZaVEJpTnpVM01qUXRObUUyWWkwME56ZGtMV0V4TldZdE1UWmhPVEptWTJSbVltVTRJaXdpZEhsd1pTSTZJa3B6YjI1VFkyaGxiV0VpZlN3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2lZMmxrSWpvaVltRm1hM0psYVdKaGRESnZhbVZzWkdWMU5YQjVZV2w1YldZMmJteHphRE42YkhkcWFHeDRkblZoWVhKbE4zZ3pZbWxzWjNOb05YcGtaWGtpTENKcFpDSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREb3dlREpoWmpkbE9HVmlabVZqTVRSbU5XVXpPVFEyT1dReVkyVTRORFF5WVRWbFpXWTVaak5tWVRRaUxDSnliMnhsSWpvaWNtVmhaQ0o5TENKcFpDSTZJbVJwWkRwdVpHRTZkR1Z6ZEc1bGREcG1aak16TURBMVlTMDNNVE5oTFRReE5USXRPR1ptWkMwNVpUTXhOR0kwT0ROa1pqUWlMQ0pwYzNOMVpYSWlPaUprYVdRNmJtUmhPblJsYzNSdVpYUTZNSGd4Tm1NMU1UTXdaR1ZtTmpRNU5tWTFaR1U1TTJZNU1EYzJZVFZqWldJd05XTmxOVGxsTkdJd0lpd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWtGMWRHaHZjbWw2WVhScGIyNURjbVZrWlc1MGFXRnNJbDBzSW5aaGJHbGtSbkp2YlNJNklqSXdNalV0TVRFdE1UbFVNVEk2TXpVNk1EVmFJaXdpZG1Gc2FXUlZiblJwYkNJNklqSXdNalV0TVRFdE1UbFVNVEk2TXpVNk1EVmFJbjE5LlJZOE9mcjQ1VEhjbGI3RWVfQXZ5MFI3WHRLcXRaOVpuSGgtMGtJOHJPTHBOM3loMWUxVjR5RVFvMldMNHVNdDNFNWM3dHhwd3V6eXktMFlScHFIbERBIl19fQ.YC9j0jNkZHJ40Y2CI9yVFSHNVdf4Zb9X_NBPlzPdllRh2gTkO1wWWm45BAGnY1Inn-HmYePqdGGwG5mgEGkJ_Q"

	filesdk.SetApplicationDID(ownerDID)

	gatewayURL := "http://localhost:8083"
	resolverURL := "https://auth-dev.pila.vn/api/v1/did"

	resolver := verificationmethod.NewResolver(resolverURL)
	customProvider := &customProvider{
		privKeyHex: ownerPrivateKeyHex,
	}

	authClient := auth.NewAuth(customProvider, resolverURL)
	client, err := filesdk.New(filesdk.Config{
		Endpoint: gatewayURL,
		Timeout:  30 * time.Second,
		Resolver: resolver,
		Auth:     authClient,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	fmt.Println("=== Downloading file ===")
	if err := download(ctx, client, ownerDID, cid, viewerJWT); err != nil {
		log.Fatalf("download failed: %v", err)
	}

	fmt.Println("\n=== Download completed successfully ===")
}

func upload(ctx context.Context, client *filesdk.Client, issuerDID, ownerDID, objectName, filePath, ownerJWT string, content []byte, ownerPrivateKeyBytes, issuerPrivateKeyBytes []byte) (string, error) {
	fmt.Printf("Uploading %q to gateway…\n", filePath)
	headers := http.Header{}
	headers.Set("Authorization", ownerJWT)
	uploadInfo, err := client.PutObject(ctx, ownerDID, objectName, bytes.NewReader(content), int64(len(content)),
		filesdk.WithAccessType(filesdk.AccessTypePrivate),
		filesdk.WithContentType("text/plain"),
		filesdk.WithIssuerDID(issuerDID),
		filesdk.WithHeaders(headers),
		filesdk.WithAccessibleSchemaID(accessibleSchemaID),
		filesdk.WithPilaAuthURL(pilaAuthURL),
		filesdk.WithSignOptions(
			provider.WithPrivateKey(ownerPrivateKeyBytes),
		),
	)
	if err != nil {
		return "", fmt.Errorf("upload object: %w", err)
	}

	fmt.Println("uploadInfo", uploadInfo)

	return uploadInfo.CID, nil
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
		filesdk.WithProviderOpts(
			crypt.WithPrivateKeyHex(ownerPrivateKeyHex),
		),
		filesdk.WithGetObjectSignOptions(
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
