// Package cmd implements the CobraCLI commands for the methodazure CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Method-Security/methodazure/internal/config"
	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// MethodAzure is the main struct for the methodazure CLI. It contains all the necessary fields to run the CLI, including
// all subcommands. It is also responsible for holding the Azure configuration, Output configuration, and Output signal
// for use by subcommands. The output signal is used to write the output of the command to the desired output format
// after the execution of the invoked commands Run function.
type MethodAzure struct {
	Version      string
	RootFlags    config.RootFlags
	AzureConfig  config.AzureConfig
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	RootCmd      *cobra.Command
	VersionCmd   *cobra.Command
}

// NewMethodAzure returns a new MethodAzure struct with the provided version string. The MethodAzure struct is used to
// initialize the root command and all subcommands that are used throughout execution of the CLI.
// We pass the version command in here from the main.go file, where we set the version string during the build process.
func NewMethodAzure(version string) *MethodAzure {
	methodAzure := MethodAzure{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:   false,
			Verbose: false,
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, datetime.DateTime(time.Now()), nil, 0, nil),
	}
	return &methodAzure
}

// InitRootCommand initializes the root command for the methodazure CLI. This command is used to set the global flags
// that are used by all subcommands, such as the region, output format, and output file. It also initializes the
// version command that prints the version of the CLI.
// Critically, this sets the PersistentPreRunE and PersistentPostRunE functions that are inherited by all subcommands.
// The PersistentPreRunE function is used to validate the cloud-config flag and set the Azure configuration. The PersistentPostRunE
// function is used to write the output of the command to the desired output format after the execution of the invoked
// command's Run function.
func (a *MethodAzure) InitRootCommand() {
	var outputFormat string
	var outputFile string

	a.RootCmd = &cobra.Command{
		Use:   "methodazure",
		Short: "methodazure CLI",
		Long:  `methodazure CLI`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			tenantID := os.Getenv("AZURE_TENANT_ID")
			if tenantID == "" {
				return errors.New("AZURE_TENANT_ID environment variable is not set")
			}
			a.AzureConfig.TenantID = tenantID

			cloudName, err := cmd.Flags().GetString("cloud-config")
			if err != nil {
				return err
			}
			switch cloudName {
			case "AzurePublic":
				a.AzureConfig.CloudConfig = cloud.AzurePublic
			case "AzureGovernment":
				a.AzureConfig.CloudConfig = cloud.AzureGovernment
			case "AzureChina":
				a.AzureConfig.CloudConfig = cloud.AzureChina
			default:
				return errors.New("invalid cloud name provided")
			}

			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				return err
			}
			a.AzureConfig.Cred = cred

			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			completedAt := datetime.DateTime(time.Now())
			a.OutputSignal.CompletedAt = &completedAt
			return writer.Write(
				a.OutputSignal.Content,
				a.OutputConfig,
				a.OutputSignal.StartedAt,
				a.OutputSignal.CompletedAt,
				a.OutputSignal.Status,
				a.OutputSignal.ErrorMessage,
			)
		},
	}

	a.RootCmd.PersistentFlags().StringP("cloud-config", "c", "AzurePublic", "Azure Cloud to use (AzurePublic, AzureGovernment, AzureChina)")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")

	a.VersionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number of methodazure",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}

	a.RootCmd.AddCommand(a.VersionCmd)
}

// A utility function to validate that the provided output format is one of the supported formats: json, yaml, signal.
func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		format = writer.YAML
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
