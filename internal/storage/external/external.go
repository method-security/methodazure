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
	stderrors "errors"
	"fmt"
	"io"
	"net"
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
// endpoint receives any HTTP response. A DNS resolution failure (the host
// simply isn't registered) means the account does not exist. Other failures
// — context cancellation, TLS handshake errors, timeouts, transient network
// errors — are propagated so seed discovery does not silently skip candidates
// under real infrastructure problems.
func accountExists(ctx context.Context, accountName, endpointSuffix string) (bool, error) {
	accountURL := "https://" + accountName + endpointSuffix + "/?comp=list"
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, accountURL, nil)
	if err != nil {
		return false, fmt.Errorf("building request for %s: %w", accountURL, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Context signals are terminal — surface them to abort discovery
		// promptly rather than misclassifying every remaining candidate.
		if stderrors.Is(err, context.Canceled) || stderrors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		// DNS "no such host" is the only signal that reliably distinguishes
		// "account does not exist" from a transient/config problem.
		var dnsErr *net.DNSError
		if stderrors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, nil
		}
		// Everything else — TLS, TCP reset, timeout, proxy — is a real
		// failure. Propagate so the caller can record it and continue with
		// the next candidate rather than silently pretending the account is
		// absent.
		return false, err
	}
	_ = resp.Body.Close()
	return true, nil
}

// probeContainer sends a HEAD request to the container URL and, when the
// container appears to allow anonymous listing, follows up with a GET list call.
//
// Returns:
//   - (container, nil)   when the container exists and is observable from an
//     anonymous client (HTTP 200 or 403 to Get Container
//     Properties). 200 with `x-ms-blob-public-access: container`
//     means public list is available; 403 means the container
//     exists but is not publicly readable.
//   - (nil, nil)         when HEAD returns 404. NOTE: 404 conflates
//     "container does not exist" with "container exists but
//     has `blob`-only public access" — Azure returns 404 to
//     anonymous Get Container Properties in the latter case
//     (see https://learn.microsoft.com/rest/api/storageservices/get-container-properties).
//     Without a known blob name we cannot distinguish the
//     two, so we skip both.
//   - (nil, err)         on transport-level failures (DNS, timeout, unexpected
//     HTTP code).
//
// containerURLStr is expected to be a canonical container URL (no path
// segments beyond the container name, no query string); callers must
// canonicalise via containerURL(...) before invoking.
func probeContainer(
	ctx context.Context,
	accountName, containerName, containerURLStr, cloudName string,
) (*storagefern.ExternalContainer, error) {
	log := svc1log.FromContext(ctx)

	// Get Container Properties requires `?restype=container`. Without it, the
	// server interprets the request as a Get Blob against the `$root` blob and
	// never emits `x-ms-blob-public-access`, so publicly-listable containers
	// look like missing ones. Build the properties URL by adding the query
	// parameter to the canonical container URL.
	propsURL, err := appendQuery(containerURLStr, "restype", "container")
	if err != nil {
		return nil, fmt.Errorf("building container-props URL for %s: %w", containerURLStr, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, propsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building HEAD request for %s: %w", propsURL, err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HEAD %s: %w", propsURL, err)
	}
	_ = resp.Body.Close()

	log.Info("Probed container",
		svc1log.SafeParam("url", propsURL),
		svc1log.SafeParam("status", resp.StatusCode))

	switch resp.StatusCode {
	case http.StatusOK, http.StatusForbidden:
		// 200 → container exists and is (potentially) publicly accessible;
		//        header disambiguates.
		// 403 → container exists but is not anonymously accessible (private
		//        or firewall-restricted). Still worth recording for
		//        existence discovery.
	case http.StatusNotFound:
		// See doc comment: 404 conflates non-existent with blob-only-public.
		// Neither is observable via anonymous container properties alone.
		return nil, nil
	default:
		// Anything else (401, 409, 3xx, 5xx, gateway timeouts, TLS-decrypted
		// error pages…) is not a reliable existence signal. Return an error
		// so the caller can log and move on rather than inventing a
		// container record from an ambiguous response — the AITF-129 class
		// of failure where 5xx from a hostile origin gets treated as "found".
		return nil, fmt.Errorf("unexpected HTTP %d probing %s", resp.StatusCode, propsURL)
	}

	publicAccessLevel := resp.Header.Get("x-ms-blob-public-access")

	// Only HTTP 200 + `x-ms-blob-public-access: container` reliably indicates
	// anonymous list capability from an unauthenticated client. Blob-only
	// public access ("blob") returns 404 to Get Container Properties (handled
	// above), so that header value is unreachable on this code path. Any 200
	// without the header, or a 403, means the container exists but is not
	// publicly listable — we still emit a record for existence discovery.
	allowAnonymousList := resp.StatusCode == http.StatusOK && publicAccessLevel == "container"
	allowAnonymousRead := allowAnonymousList

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
// blobs as BlobInfo structs. containerURLStr must be a canonical container URL
// (no existing query string); callers canonicalise via containerURL(...).
func listBlobs(ctx context.Context, containerURLStr string) ([]*storagefern.BlobInfo, error) {
	// Build the list URL safely: even though callers pass a canonical URL,
	// use url.Parse so any future path/query drift doesn't produce a
	// malformed request.
	listURL, err := buildListBlobsURL(containerURLStr)
	if err != nil {
		return nil, fmt.Errorf("building list URL for %s: %w", containerURLStr, err)
	}
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

	rawURL := *config.Url
	log.Info("Starting external Azure Blob Storage enumeration",
		svc1log.SafeParam("containerURL", rawURL))

	urlAccountName, urlContainerName, urlEndpointSuffix := parseContainerURL(rawURL)
	if urlAccountName == "" || urlContainerName == "" {
		errors = append(errors, fmt.Sprintf(
			"could not parse account and container name from URL %q; expected https://<account>.blob.core.<suffix>/<container>",
			rawURL,
		))
		report.Result = &result
		report.Errors = errors
		return report
	}

	// Preserve the cloud implied by the caller URL rather than the value of
	// --cloud-config. Otherwise a Government or China URL would be probed
	// against the public endpoint (or attributed to the wrong cloud in the
	// resulting ExternalContainer.Identification).
	urlCloudName := cloudFromEndpointSuffix(urlEndpointSuffix)
	if urlCloudName != cloudName {
		log.Info("URL implies a different cloud than --cloud-config; using the URL's cloud",
			svc1log.SafeParam("urlCloud", urlCloudName),
			svc1log.SafeParam("flagCloud", cloudName))
		cloudName = urlCloudName
		endpointSuffix = urlEndpointSuffix
	}

	// Canonicalise so probeContainer + listBlobs work on a URL with no
	// stray path segments or query parameters. The caller's URL might
	// include a trailing blob path or query string that would break both
	// the container-properties HEAD (adds `?restype=container`) and the
	// list-blobs GET (adds `?restype=container&comp=list`).
	containerURLStr := containerURL(urlAccountName, urlContainerName, endpointSuffix)

	container, err := probeContainer(ctx, urlAccountName, urlContainerName, containerURLStr, cloudName)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error probing container: %v", err))
	} else if container == nil {
		// 404 to Get Container Properties, which conflates non-existent
		// with blob-only public access. See probeContainer doc.
		errors = append(errors, fmt.Sprintf("Container not found or not observable at %s", containerURLStr))
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
