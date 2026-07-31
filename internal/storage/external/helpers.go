// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

package external

import (
	// Standard
	"net/url"
	"strings"
)

// parseContainerURL extracts the storage account name and container name from
// a well-formed Azure Blob Storage container URL.
//
// Supported forms:
//
//	https://<account>.blob.core.windows.net/<container>
//	https://<account>.blob.core.windows.net/<container>/<blobpath...>
//	https://<account>.blob.core.usgovcloudapi.net/<container>
//	https://<account>.blob.core.chinacloudapi.cn/<container>
//
// Returns ("", "") when the URL cannot be parsed into account + container.
func parseContainerURL(raw string) (accountName, containerName string) {
	if raw == "" {
		return "", ""
	}

	// Add scheme if missing so url.Parse sees a Host.
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}

	host := strings.ToLower(u.Host)
	if host == "" {
		return "", ""
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
			break
		}
	}
	if accountName == "" {
		return "", ""
	}

	// First non-empty path segment is the container name.
	containerName = firstPathSegment(u.Path)
	return accountName, containerName
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
