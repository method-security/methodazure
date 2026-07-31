// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

// Package external provides anonymous (credential-free) probing of Azure Blob
// Storage containers to detect public-access misconfiguration.
package external

import (
	// Standard
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	// Generated
	storagefern "github.com/Method-Security/methodazure/generated/go/storage"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// httpClient is a shared HTTP client with a reasonable timeout for anonymous
// probes. It follows redirects (default behaviour) and does not send credentials.
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
}

// azureListBlobsResponse models the minimal XML returned by the Azure Blob
// Storage list-blobs REST call.
type azureListBlobsResponse struct {
	XMLName xml.Name         `xml:"EnumerationResults"`
	Blobs   []azureBlobEntry `xml:"Blobs>Blob"`
}

type azureBlobEntry struct {
	Name       string         `xml:"Name"`
	Properties azureBlobProps `xml:"Properties"`
}

type azureBlobProps struct {
	LastModified  string `xml:"Last-Modified"`
	ContentLength int    `xml:"Content-Length"`
	ContentType   string `xml:"Content-Type"`
}

// accountExists returns true when a HEAD request to the account's root
// endpoint receives any non-connection-error response.  A DNS failure means
// the account does not exist; any HTTP response (even 4xx) means it does.
func accountExists(ctx context.Context, accountName, endpointSuffix string) (bool, error) {
	accountURL := "https://" + accountName + endpointSuffix + "/?comp=list"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, accountURL, nil)
	if err != nil {
		return false, fmt.Errorf("building request for %s: %w", accountURL, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection / DNS failure → account does not exist.
		return false, nil //nolint:nilerr
	}
	_ = resp.Body.Close()
	return true, nil
}

// probeContainer sends a HEAD request to the container URL and, when the
// container appears to allow anonymous listing, follows up with a GET list call.
//
// Returns:
//   - (container, nil)   when the container exists and is non-404
//   - (nil, nil)         when HEAD returns 404 (container does not exist)
//   - (nil, err)         on unexpected errors
func probeContainer(
	ctx context.Context,
	accountName, containerName, containerURLStr, cloudName string,
) (*storagefern.ExternalContainer, error) {
	log := svc1log.FromContext(ctx)

	// HEAD the container URL to test existence and read public-access level.
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, containerURLStr, nil)
	if err != nil {
		return nil, fmt.Errorf("building HEAD request for %s: %w", containerURLStr, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", containerURLStr, err)
	}
	_ = resp.Body.Close()

	log.Info("Probed container",
		svc1log.SafeParam("url", containerURLStr),
		svc1log.SafeParam("status", resp.StatusCode))

	if resp.StatusCode == http.StatusNotFound {
		// Container does not exist — skip without error.
		return nil, nil
	}

	// Any non-404 response → the container exists; record what we know.
	publicAccessLevel := resp.Header.Get("x-ms-blob-public-access")

	// Derive access flags from the public-access-level header value.
	// "container" → both list and read allowed
	// "blob"      → only anonymous blob read allowed (no list)
	// absent      → container exists but is private (403 etc.)
	allowAnonymousList := publicAccessLevel == "container"
	allowAnonymousRead := publicAccessLevel == "container" || publicAccessLevel == "blob"

	identification := &storagefern.ExternalContainerIdentificationInfo{
		AccountName:   accountName,
		ContainerName: containerName,
		Url:           containerURLStr,
		Cloud:         cloudName,
	}

	var palStr *string
	if publicAccessLevel != "" {
		palStr = &publicAccessLevel
	}
	configuration := &storagefern.ExternalContainerConfigurationInfo{
		AllowAnonymousList: allowAnonymousList,
		AllowAnonymousRead: allowAnonymousRead,
		PublicAccessLevel:  palStr,
	}

	container := &storagefern.ExternalContainer{
		Identification: identification,
		Configuration:  configuration,
	}

	// When list is allowed, attempt to enumerate blobs.
	if allowAnonymousList {
		blobs, listErr := listBlobs(ctx, containerURLStr)
		if listErr != nil {
			log.Warn("Failed to list blobs",
				svc1log.SafeParam("containerURL", containerURLStr),
				svc1log.SafeParam("error", listErr.Error()))
		} else if len(blobs) > 0 {
			container.Resources = &storagefern.ExternalContainerResourceInfo{
				Blobs: blobs,
			}
		}
	}

	return container, nil
}

// listBlobs performs an anonymous GET list-blobs request and returns up to 100
// blobs as BlobInfo structs.
func listBlobs(ctx context.Context, containerURLStr string) ([]*storagefern.BlobInfo, error) {
	listURL := containerURLStr + "?restype=container&comp=list"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building list request for %s: %w", listURL, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", listURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list blobs returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading list response: %w", err)
	}

	var enumResult azureListBlobsResponse
	if err := xml.Unmarshal(body, &enumResult); err != nil {
		return nil, fmt.Errorf("parsing list XML: %w", err)
	}

	const maxBlobs = 100
	blobs := make([]*storagefern.BlobInfo, 0, len(enumResult.Blobs))
	for i, entry := range enumResult.Blobs {
		if i >= maxBlobs {
			break
		}
		blob := &storagefern.BlobInfo{
			Name: entry.Name,
		}
		if entry.Properties.ContentLength > 0 {
			size := entry.Properties.ContentLength
			blob.Size = &size
		}
		if entry.Properties.ContentType != "" {
			ct := entry.Properties.ContentType
			blob.ContentType = &ct
		}
		if entry.Properties.LastModified != "" {
			// RFC1123 / RFC2616 date format used by Azure REST API
			t, parseErr := time.Parse(time.RFC1123, entry.Properties.LastModified)
			if parseErr == nil {
				blob.LastModified = &t
			}
		}
		blobs = append(blobs, blob)
	}
	return blobs, nil
}

// EnumerateStorage is the public entry point.  It either probes a single
// container URL (when config.Url is set) or runs seed-based discovery (when
// config.TargetSeed is set).
func EnumerateStorage(ctx context.Context, config storagefern.ExternalStorageConfig) storagefern.ExternalStorageReport {
	log := svc1log.FromContext(ctx)

	cloudName := "AzurePublic"
	if config.Cloud != nil && *config.Cloud != "" {
		cloudName = *config.Cloud
	}
	endpointSuffix := blobEndpointSuffix(cloudName)

	report := storagefern.ExternalStorageReport{
		Config: &config,
	}
	result := storagefern.ExternalStorageResult{}
	errors := []string{}

	// Seed-based discovery takes precedence when provided.
	if config.TargetSeed != nil && strings.TrimSpace(*config.TargetSeed) != "" {
		seedResult, seedErrors := enumerateBySeed(ctx, config, cloudName, endpointSuffix)
		if config.Url != nil && *config.Url != "" {
			log.Warn("Both url and targetSeed provided; enumerating by seed and ignoring url",
				svc1log.SafeParam("url", *config.Url))
			seedErrors = append(seedErrors, fmt.Sprintf(
				"both url and targetSeed were provided; enumerated by seed and ignored url %q", *config.Url,
			))
		}
		report.Result = seedResult
		report.Errors = seedErrors
		return report
	}

	if config.Url == nil || *config.Url == "" {
		report.Result = &result
		report.Errors = []string{"either url or targetSeed must be provided"}
		return report
	}

	containerURLStr := *config.Url
	log.Info("Starting external Azure Blob Storage enumeration",
		svc1log.SafeParam("containerURL", containerURLStr))

	accountName, containerName := parseContainerURL(containerURLStr)
	if accountName == "" || containerName == "" {
		errors = append(errors, fmt.Sprintf(
			"could not parse account and container name from URL %q; expected https://<account>.blob.core.<suffix>/<container>",
			containerURLStr,
		))
		report.Result = &result
		report.Errors = errors
		return report
	}

	container, err := probeContainer(ctx, accountName, containerName, containerURLStr, cloudName)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error probing container: %v", err))
	} else if container == nil {
		errors = append(errors, fmt.Sprintf("Container not found at %s", containerURLStr))
	} else {
		result.ExternalContainers = append(result.ExternalContainers, container)
	}

	report.Result = &result
	report.Errors = errors

	log.Info("External Azure Blob Storage enumeration completed",
		svc1log.SafeParam("containersFound", len(result.ExternalContainers)),
		svc1log.SafeParam("totalErrors", len(errors)))

	return report
}
