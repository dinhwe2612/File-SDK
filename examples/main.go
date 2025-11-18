package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	filesdk "github.com/dinhwe2612/file-sdk"
)

var (
	issuerDID           = "did:nda:testnet:0x2af7e8ebfec14f5e39469d2ce8442a5eef9f3fa4"
	issuerPrivateKeyHex = "ed9b1db01a02b9779f9631ad591c47d14dc4358649fd76f09fbc97c77a320d4f"
	ownerDID            = "did:nda:testnet:0x16c5130def6496f5de93f9076a5ceb05ce59e4b0"
	ownerPrivateKeyHex  = "c91fdc404bf67d3b3c5f8961bd20273d4498bd27c1675acaf3515ab305ea2786"
)

func main() {
	ctx := context.Background()

	// Create a client pointing to the gateway endpoint
	gatewayURL := "http://localhost:8083/api/v1" // Adjust to your gateway URL
	client, err := filesdk.New(filesdk.Config{
		Endpoint: gatewayURL,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	resolverURL := "https://auth-dev.pila.vn/api/v1/did" // Replace with your DID resolver endpoint
	// Load file content to upload. Prefer the example's go.mod; fall back to local go.mod.
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

	// Step 1: Upload the file
	fmt.Println("=== Step 1: Uploading file ===")
	cid, err := upload(ctx, client, issuerDID, ownerDID, resolverURL, objectName, filePath, content)
	if err != nil {
		log.Fatalf("upload failed: %v", err)
	}

	// Step 2: Print CID and wait for user input
	fmt.Println("\n=== Step 2: Upload successful ===")
	fmt.Printf("CID: %s\n", cid)
	fmt.Println("\nPlease enter the viewerJWT to download the file:")
	fmt.Print("viewerJWT: ")

	reader := bufio.NewReader(os.Stdin)
	viewerJWT, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("failed to read viewerJWT: %v", err)
	}
	viewerJWT = strings.TrimSpace(viewerJWT)
	if viewerJWT == "" {
		log.Fatal("viewerJWT cannot be empty")
	}

	// Step 3: Download the file using the viewerJWT
	fmt.Println("\n=== Step 3: Downloading file ===")
	if err := download(ctx, client, ownerDID, cid, viewerJWT); err != nil {
		log.Fatalf("download failed: %v", err)
	}

	fmt.Println("\n=== Workflow completed successfully ===")
}

func upload(ctx context.Context, client *filesdk.Client, issuerDID, ownerDID, resolverURL, objectName, filePath string, content []byte) (string, error) {
	fmt.Printf("Uploading %q to gateway…\n", filePath)
	uploadInfo, err := client.PutObject(ctx, ownerDID, objectName, bytes.NewReader(content), int64(len(content)), filesdk.PutObjectOptions{
		AccessType:  filesdk.AccessTypePrivate,
		ContentType: "text/plain",
		IssuerDID:   issuerDID,
		ResolverURL: resolverURL,
	})
	if err != nil {
		return "", fmt.Errorf("upload object: %w", err)
	}

	return uploadInfo.Key, nil
}

func download(ctx context.Context, client *filesdk.Client, ownerDID, cid, viewerJWT string) error {
	if viewerJWT == "" {
		return fmt.Errorf("missing viewer JWT for Authorization header")
	}

	headers := http.Header{}
	headers.Set("Authorization", viewerJWT)

	fmt.Println("Fetching object back from gateway…")
	obj, err := client.GetObject(ctx, ownerDID, cid, filesdk.GetObjectOptions{
		Headers:       headers,
		PrivateKeyHex: issuerPrivateKeyHex,
	})
	if err != nil {
		return fmt.Errorf("get object: %w", err)
	}
	defer obj.Close()

	info, err := obj.Stat()
	if err != nil {
		return fmt.Errorf("stat object: %w", err)
	}

	fmt.Printf("Object Info:\n")
	fmt.Printf("  CID: %s\n", info.Key)
	fmt.Printf("  Content-Type: %s\n", info.ContentType)
	fmt.Printf("  Size: %d bytes\n", info.Size)

	// 3. Stream the file content.
	var total int
	buf := make([]byte, 1024)
	for {
		n, err := obj.Read(buf)
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
