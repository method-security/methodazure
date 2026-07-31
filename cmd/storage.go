// Copyright (c) 2024 Method Security. All rights reserved.
// Use of this source code is governed by the MIT license that can be found
// in the LICENSE file.

// Package cmd implements the CobraCLI commands for the methodazure CLI.
package cmd

import (
	// Standard
	"fmt"
	"strings"

	// Internal
	"github.com/Method-Security/methodazure/internal/config"
	"github.com/Method-Security/methodazure/internal/storage/external"

	// Generated
	storagefern "github.com/Method-Security/methodazure/generated/go/storage"
	// External
	"github.com/Method-Security/pkg/writer"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitStorageCommand initializes the `methodazure storage` subcommand hierarchy,
// which deals with enumerating Azure Blob Storage containers and their resources.
func (a *MethodAzure) InitStorageCommand() {
	storageCmd := &cobra.Command{
		Use:   "storage",
		Short: "Audit and manage Azure Blob Storage services.",
		Long:  `Audit and manage Azure Blob Storage services.`,
	}

	// external subcommand -------------------------------------------------------
	// PersistentPreRunE is overridden here to skip Azure credential setup because
	// the external command uses anonymous HTTP probing — no AZURE_TENANT_ID or
	// DefaultAzureCredential is needed.  Output-format resolution and cloud-config
	// parsing are still performed so the signal output and endpoint suffix work.
	externalCmd := &cobra.Command{
		Use:   "external",
		Short: "Enumerate public-facing Azure Blob Storage containers from an external perspective.",
		Long: `Enumerate public-facing Azure Blob Storage containers from an external perspective.

Probes are fully anonymous (no Azure credentials required).  Either a direct
container URL or an org/domain seed for candidate-name discovery must be
provided, but not both.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Override the parent's PersistentPreRunE — we do NOT require
			// AZURE_TENANT_ID and do NOT call NewDefaultAzureCredential.
			outputFormat, _ := cmd.Root().PersistentFlags().GetString("output")
			outputFile, _ := cmd.Root().PersistentFlags().GetString("output-file")

			// Resolve output writer config.
			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePtr *string
			if outputFile != "" {
				outputFilePtr = &outputFile
			}

			// Resolve cloud config (needed for building blob endpoint URLs).
			cloudName, err := cmd.Root().PersistentFlags().GetString("cloud-config")
			if err != nil {
				return err
			}
			// Validate that the cloud config value is one we recognise.
			switch cloudName {
			case "AzurePublic", "AzureGovernment", "AzureChina":
				// valid
			default:
				return fmt.Errorf("invalid cloud name provided: %q (valid: AzurePublic, AzureGovernment, AzureChina)", cloudName)
			}

			// Store the cloud name on AzureConfig.TenantID field is deliberately
			// left empty — anonymous probing does not need it.  The cloudName is
			// passed through to the internal probe via the Fern config struct.
			a.AzureConfig.TenantID = ""

			// Initialise the output writer.
			a.OutputConfig = writer.NewOutputConfig(outputFilePtr, format)

			// Set up structured logging.
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			// Retrieve --url flag.
			containerURL, err := cmd.Flags().GetString("url")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Retrieve --target-seed flag; treat whitespace-only as unset.
			targetSeed, err := cmd.Flags().GetString("target-seed")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			targetSeed = strings.TrimSpace(targetSeed)

			// Retrieve --max-candidates flag.
			maxCandidates, err := cmd.Flags().GetInt("max-candidates")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Exactly one of --url or --target-seed must be supplied.
			if containerURL == "" && targetSeed == "" {
				a.OutputSignal.AddError(fmt.Errorf("either --url or --target-seed must be provided"))
				return
			}
			if containerURL != "" && targetSeed != "" {
				a.OutputSignal.AddError(fmt.Errorf("provide either --url or --target-seed, not both"))
				return
			}

			// Resolve cloud name for endpoint suffix and container identification.
			cloudName, _ := cmd.Root().PersistentFlags().GetString("cloud-config")

			// Build the Fern config struct.
			config := buildExternalStorageConfig(containerURL, targetSeed, maxCandidates, cloudName)

			// Run the probe.
			report := external.EnumerateStorage(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Flags for the external subcommand.
	externalCmd.Flags().String("url", "", "URL of a single Azure Blob Storage container to probe (https://<account>.blob.core.windows.net/<container>)")
	externalCmd.Flags().String("target-seed", "", "Org/domain seed used to generate and probe candidate Azure storage account names")
	externalCmd.Flags().Int("max-candidates", 50, "Max candidate account names to probe when --target-seed is set (cap 500)")

	storageCmd.AddCommand(externalCmd)
	a.RootCmd.AddCommand(storageCmd)
}

// buildExternalStorageConfig returns an ExternalStorageConfig populated from
// the CLI flags.
func buildExternalStorageConfig(containerURL, targetSeed string, maxCandidates int, cloudName string) storagefern.ExternalStorageConfig {
	config := storagefern.ExternalStorageConfig{}
	if containerURL != "" {
		config.Url = &containerURL
	}
	if targetSeed != "" {
		config.TargetSeed = &targetSeed
		config.MaxCandidates = &maxCandidates
	}
	if cloudName != "" {
		config.Cloud = &cloudName
	}
	return config
}
