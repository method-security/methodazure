// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

package external

import (
	"testing"
)

func TestParseContainerURL(t *testing.T) {
	tests := []struct {
		name              string
		url               string
		wantAccountName   string
		wantContainerName string
	}{
		{
			name:              "AzurePublic URL",
			url:               "https://leakybatcave.blob.core.windows.net/public",
			wantAccountName:   "leakybatcave",
			wantContainerName: "public",
		},
		{
			name:              "AzureGovernment URL",
			url:               "https://govaccount.blob.core.usgovcloudapi.net/backups",
			wantAccountName:   "govaccount",
			wantContainerName: "backups",
		},
		{
			name:              "AzureChina URL",
			url:               "https://chinastore.blob.core.chinacloudapi.cn/data",
			wantAccountName:   "chinastore",
			wantContainerName: "data",
		},
		{
			name:              "URL with trailing blob path",
			url:               "https://myaccount.blob.core.windows.net/mycontainer/subdir/file.txt",
			wantAccountName:   "myaccount",
			wantContainerName: "mycontainer",
		},
		{
			name:              "URL without scheme",
			url:               "myaccount.blob.core.windows.net/mycontainer",
			wantAccountName:   "myaccount",
			wantContainerName: "mycontainer",
		},
		{
			name:              "Empty URL",
			url:               "",
			wantAccountName:   "",
			wantContainerName: "",
		},
		{
			name:              "Non-blob URL returns empty",
			url:               "https://example.com/somepath",
			wantAccountName:   "",
			wantContainerName: "",
		},
		{
			name:              "Account-only URL — no container",
			url:               "https://myaccount.blob.core.windows.net/",
			wantAccountName:   "myaccount",
			wantContainerName: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotAccount, gotContainer := parseContainerURL(tc.url)
			if gotAccount != tc.wantAccountName {
				t.Errorf("parseContainerURL(%q) accountName = %q, want %q", tc.url, gotAccount, tc.wantAccountName)
			}
			if gotContainer != tc.wantContainerName {
				t.Errorf("parseContainerURL(%q) containerName = %q, want %q", tc.url, gotContainer, tc.wantContainerName)
			}
		})
	}
}

func TestBlobEndpointSuffix(t *testing.T) {
	tests := []struct {
		cloud string
		want  string
	}{
		{"AzurePublic", ".blob.core.windows.net"},
		{"AzureGovernment", ".blob.core.usgovcloudapi.net"},
		{"AzureChina", ".blob.core.chinacloudapi.cn"},
		{"", ".blob.core.windows.net"},
		{"unknown", ".blob.core.windows.net"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.cloud, func(t *testing.T) {
			got := blobEndpointSuffix(tc.cloud)
			if got != tc.want {
				t.Errorf("blobEndpointSuffix(%q) = %q, want %q", tc.cloud, got, tc.want)
			}
		})
	}
}
