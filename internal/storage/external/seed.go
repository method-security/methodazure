// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

package external

import (
	// Standard
	"context"
	"fmt"
	"regexp"
	"strings"

	// Generated
	storagefern "github.com/Method-Security/methodazure/generated/go/storage"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// permutationSuffixes lists the candidate-name suffixes used during seed expansion.
// Azure storage account names may not contain hyphens, so all suffixes are
// hyphen-free (unlike the AWS S3 equivalents which use hyphens freely).
var permutationSuffixes = []string{
	"",
	"prod",
	"production",
	"staging",
	"stage",
	"dev",
	"test",
	"qa",
	"logs",
	"log",
	"artifacts",
	"assets",
	"static",
	"public",
	"private",
	"data",
	"files",
	"uploads",
	"media",
	"archive",
	"backups",
	"backup",
	"cdn",
	"web",
	"app",
	"config",
	"storage",
	"builds",
	"releases",
}

// commonContainerNames is the list of container names probed for each discovered
// storage account during seed-based discovery.
var commonContainerNames = []string{
	"public",
	"backup",
	"backups",
	"assets",
	"content",
	"images",
	"media",
	"static",
	"data",
	"files",
	"docs",
	"logs",
	"web",
	"www",
}

const (
	defaultMaxCandidates = 50
	maxCandidatesCap     = 500
)

var (
	// Azure storage account names: 3-24 chars, lowercase letters and digits only.
	// No hyphens, no dots — simpler than S3 bucket names.
	validAccountName = regexp.MustCompile(`^[a-z][a-z0-9]{1,22}[a-z0-9]$`)

	// Used to strip non-alphanumeric chars when normalising the seed.
	nonAlphanumRun = regexp.MustCompile(`[^a-z0-9]+`)
	leadingWww     = regexp.MustCompile(`^www\.`)
)

// normalizeSeedVariants derives candidate base names from a seed (org name,
// domain, or URL). Returns a de-duplicated, non-empty slice of lowercase
// alphanumeric strings suitable for use as Azure storage account name prefixes.
func normalizeSeedVariants(targetSeed string) []string {
	seed := strings.ToLower(strings.TrimSpace(targetSeed))

	// Strip URL scheme.
	if idx := strings.Index(seed, "://"); idx >= 0 {
		seed = seed[idx+3:]
	}
	// Strip path, query, port.
	seed = strings.SplitN(seed, "/", 2)[0]
	seed = strings.SplitN(seed, ":", 2)[0]
	seed = strings.Trim(seed, ".")
	seed = leadingWww.ReplaceAllString(seed, "")

	// Compact to lowercase alphanumeric only.
	compact := nonAlphanumRun.ReplaceAllString(seed, "")

	// Also try stripping TLD to get the bare org name.
	noTLD := compact
	if strings.Contains(seed, ".") {
		labels := strings.FieldsFunc(seed, func(r rune) bool { return r == '.' })
		if len(labels) >= 2 {
			noTLD = nonAlphanumRun.ReplaceAllString(labels[len(labels)-2], "")
		}
	}

	variants := []string{compact, noTLD}
	return dedupeNonEmpty(variants)
}

// dedupeNonEmpty returns a deduplicated slice with empty strings removed.
func dedupeNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

// candidateAccountNames expands seed variants with permutation suffixes to
// produce a list of candidate Azure storage account names, capped at
// maxCandidates (clamped to [1, maxCandidatesCap]).
func candidateAccountNames(targetSeed string, maxCandidates int) []string {
	if maxCandidates < 1 {
		maxCandidates = 1
	}
	if maxCandidates > maxCandidatesCap {
		maxCandidates = maxCandidatesCap
	}

	variants := normalizeSeedVariants(targetSeed)
	candidates := make([]string, 0, maxCandidates)
	seen := make(map[string]struct{}, maxCandidates)

	// Iterate suffix-major so every variant's bare name is probed before any
	// variant's lower-priority suffix (mirrors methodaws seed.go convention).
	for _, suffix := range permutationSuffixes {
		for _, base := range variants {
			name := base + suffix
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			if !isValidAccountName(name) {
				continue
			}
			candidates = append(candidates, name)
			if len(candidates) >= maxCandidates {
				return candidates
			}
		}
	}
	return candidates
}

// isValidAccountName returns true when name satisfies Azure storage account
// name rules: 3–24 chars, lowercase letters and digits only, starts with a
// letter, ends with a letter or digit.
func isValidAccountName(name string) bool {
	return len(name) >= 3 && len(name) <= 24 && validAccountName.MatchString(name)
}

// enumerateBySeed generates candidate account names from the seed, checks
// whether each account exists (via a lightweight HTTP probe), and for each
// discovered account probes common container names.
func enumerateBySeed(
	ctx context.Context,
	config storagefern.ExternalStorageConfig,
	cloudName, endpointSuffix string,
) (*storagefern.ExternalStorageResult, []string) {
	log := svc1log.FromContext(ctx)
	result := &storagefern.ExternalStorageResult{}
	errors := []string{}

	maxCandidates := defaultMaxCandidates
	if config.MaxCandidates != nil {
		maxCandidates = *config.MaxCandidates
	}

	candidates := candidateAccountNames(*config.TargetSeed, maxCandidates)
	log.Info("Starting seed-based Azure Blob Storage account discovery",
		svc1log.SafeParam("targetSeed", *config.TargetSeed),
		svc1log.SafeParam("candidateCount", len(candidates)))

	if len(candidates) == 0 {
		errors = append(errors, fmt.Sprintf(
			"no valid Azure storage account name candidates could be derived from target seed %q",
			*config.TargetSeed,
		))
		return result, errors
	}

	for _, accountName := range candidates {
		exists, err := accountExists(ctx, accountName, endpointSuffix)
		if err != nil {
			log.Warn("Error checking candidate storage account",
				svc1log.SafeParam("accountName", accountName),
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, fmt.Sprintf("Error checking storage account %s: %v", accountName, err))
			continue
		}
		if !exists {
			continue
		}

		log.Info("Discovered storage account",
			svc1log.SafeParam("accountName", accountName))

		// Probe common container names for this account.
		for _, containerName := range commonContainerNames {
			containerURLStr := containerURL(accountName, containerName, endpointSuffix)
			container, err := probeContainer(ctx, accountName, containerName, containerURLStr, cloudName)
			if err != nil {
				errors = append(errors, fmt.Sprintf(
					"Error probing container %s/%s: %v", accountName, containerName, err,
				))
				continue
			}
			if container != nil {
				result.ExternalContainers = append(result.ExternalContainers, container)
			}
		}
	}

	if len(result.ExternalContainers) == 0 {
		errors = append(errors, fmt.Sprintf(
			"no public containers found among %d candidate accounts derived from target seed %q",
			len(candidates), *config.TargetSeed,
		))
	}

	log.Info("Completed seed-based Azure Blob Storage discovery",
		svc1log.SafeParam("targetSeed", *config.TargetSeed),
		svc1log.SafeParam("containersFound", len(result.ExternalContainers)))

	return result, errors
}
