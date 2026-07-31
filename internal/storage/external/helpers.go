// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

package external

import (
	// Standard
	"net/url"
	"strings"
)

// parseContainerURL extracts the storage account name, container name, and
// endpoint suffix from a well-formed Azure Blob Storage container URL.
//
// Supported forms:
//
//	https://<account>.blob.core.windows.net/<container>
//	https://<account>.blob.core.windows.net/<container>/<blobpath...>
//	https://<account>.blob.core.usgovcloudapi.net/<container>
//	https://<account>.blob.core.chinacloudapi.cn/<container>
//
// The endpoint suffix is returned so callers building canonical URLs can
// preserve the cloud implied by the caller URL (rather than defaulting to
// the AzurePublic endpoint driven by --cloud-config).
//
// Returns ("", "", "") when the URL cannot be parsed into account + container.
func parseContainerURL(raw string) (accountName, containerName, endpointSuffix string) {
	if raw == "" {
		return "", "", ""
	}

	// Add scheme if missing so url.Parse sees a Host.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", ""
	}

	host := strings.ToLower(u.Host)
	if host == "" {
		return "", "", ""
	}

	// Host must look like <account>.blob.core.<suffix>.
	// We accept any of the three cloud suffixes.
	blobSuffixes := []string{
		".blob.core.windows.net",
		".blob.core.usgovcloudapi.net",
		".blob.core.chinacloudapi.cn",
	}
	for _, suffix := range blobSuffixes {
		if strings.HasSuffix(host, suffix) {
			accountName = strings.TrimSuffix(host, suffix)
			endpointSuffix = suffix
			break
		}
	}
	if accountName == "" {
		return "", "", ""
	}

	// First non-empty path segment is the container name.
	containerName = firstPathSegment(u.Path)
	return accountName, containerName, endpointSuffix
}

// cloudFromEndpointSuffix maps a parsed endpoint suffix back to its cloud
// name string. Used in --url mode to attribute a finding to the correct
// cloud rather than blindly using the --cloud-config value.
func cloudFromEndpointSuffix(suffix string) string {
	switch suffix {
	case ".blob.core.usgovcloudapi.net":
		return "AzureGovernment"
	case ".blob.core.chinacloudapi.cn":
		return "AzureChina"
	default:
		return "AzurePublic"
	}
}

// firstPathSegment returns the first non-empty segment of a URL path.
func firstPathSegment(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return ""
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	// Strip any query that ended up in the path (defensive).
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// blobEndpointSuffix returns the blob endpoint DNS suffix for the given cloud
// name string ("AzurePublic", "AzureGovernment", "AzureChina").
func blobEndpointSuffix(cloud string) string {
	switch cloud {
	case "AzureGovernment":
		return ".blob.core.usgovcloudapi.net"
	case "AzureChina":
		return ".blob.core.chinacloudapi.cn"
	default:
		// AzurePublic or anything unrecognised — use the public endpoint.
		return ".blob.core.windows.net"
	}
}

// containerURL assembles a canonical container URL from account, container, and
// the cloud-specific endpoint suffix.
func containerURL(accountName, containerName, endpointSuffix string) string {
	return "https://" + accountName + endpointSuffix + "/" + containerName
}

// appendQuery returns urlStr with (key, value) added to its query string.
// If urlStr already has a query, the new pair is merged in. This avoids the
// malformed URLs that come from naive `?a=b` string concatenation onto a URL
// that already carries a query.
func appendQuery(urlStr, key, value string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// buildListBlobsURL constructs the Azure Blob Storage list-blobs REST URL
// from a canonical container URL. It uses url.Parse so callers who pass
// non-canonical URLs (with existing query strings) still get a well-formed
// list URL rather than a malformed `...?a=b?restype=container&comp=list`.
//
// maxresults=100 is set explicitly so Azure caps the response at 100 entries,
// which prevents large public containers from returning thousands of blobs,
// truncating mid-XML at the 4 MB read limit, and causing parse failures.
// The value matches the maxBlobs constant enforced in the caller.
func buildListBlobsURL(containerURLStr string) (string, error) {
	u, err := url.Parse(containerURLStr)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("restype", "container")
	q.Set("comp", "list")
	q.Set("maxresults", "100")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
