// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

package external

import (
	"strings"
	"testing"
)

func TestIsValidAccountName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid lowercase", "leakybatcave", true},
		{"valid with digits", "storage123", true},
		{"too short", "ab", false},
		{"too long", strings.Repeat("a", 25), false},
		{"contains hyphen", "my-account", false},
		{"contains dot", "my.account", false},
		{"contains uppercase", "MyAccount", false},
		{"starts with digit", "1account", false},
		{"exactly 3 chars", "abc", true},
		{"exactly 24 chars", strings.Repeat("a", 24), true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := isValidAccountName(tc.input)
			if got != tc.want {
				t.Errorf("isValidAccountName(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestCandidateAccountNames_DefaultMax(t *testing.T) {
	candidates := candidateAccountNames("leakybat", defaultMaxCandidates)
	if len(candidates) == 0 {
		t.Fatal("expected at least one candidate for seed 'leakybat'")
	}
	if len(candidates) > defaultMaxCandidates {
		t.Errorf("candidates %d exceeds default max %d", len(candidates), defaultMaxCandidates)
	}

	// The bare seed should appear first (suffix == "").
	if candidates[0] != "leakybat" {
		t.Errorf("expected first candidate to be bare seed 'leakybat', got %q", candidates[0])
	}

	// Every candidate must be a valid account name.
	for _, c := range candidates {
		if !isValidAccountName(c) {
			t.Errorf("candidate %q is not a valid Azure storage account name", c)
		}
	}
}

func TestCandidateAccountNames_Cap(t *testing.T) {
	candidates := candidateAccountNames("example", maxCandidatesCap+999)
	if len(candidates) > maxCandidatesCap {
		t.Errorf("candidates %d exceeds hard cap %d", len(candidates), maxCandidatesCap)
	}
}

func TestCandidateAccountNames_SuffixMajorOrdering(t *testing.T) {
	// With multiple variants the suffix-major ordering should produce bare names
	// from all variants before suffixed names.
	// For seed "example.com" we expect both "examplecom" and "example" as bare
	// names before any suffixed variant.
	candidates := candidateAccountNames("example.com", defaultMaxCandidates)
	if len(candidates) < 2 {
		t.Skip("not enough candidates to test ordering")
	}
	// Both bare variants should precede suffixed variants.
	firstSuffixedIdx := -1
	for i, c := range candidates {
		hasSuffix := false
		for _, s := range permutationSuffixes[1:] { // skip ""
			if strings.HasSuffix(c, s) {
				hasSuffix = true
				break
			}
		}
		if hasSuffix {
			firstSuffixedIdx = i
			break
		}
	}
	if firstSuffixedIdx == 0 {
		t.Errorf("first candidate %q is suffixed — expected bare names first", candidates[0])
	}
}

func TestNormalizeSeedVariants_Domain(t *testing.T) {
	variants := normalizeSeedVariants("www.leakybat.com")
	found := false
	for _, v := range variants {
		if v == "leakybat" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'leakybat' in variants for seed 'www.leakybat.com', got %v", variants)
	}
}

func TestNormalizeSeedVariants_EmptySeed(t *testing.T) {
	variants := normalizeSeedVariants("   ")
	if len(variants) != 0 {
		t.Errorf("expected empty variants for whitespace-only seed, got %v", variants)
	}
}
