package cmd

import (
	"github.com/Method-Security/methodazure/internal/iam"
	"github.com/spf13/cobra"
)

// InitIAMCommand initializes the `methodazure iam` subcommand that deals with enumerating IAM related resources in the Azure environment.
func (a *MethodAzure) InitIAMCommand() {
	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Audit and command IAM related resources",
		Long:  `Audit and command IAM related resourcess`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate IAM related resources in a given subscription",
		Long:  `Enumerate IAM related resources; retreives roles and role assignments in a given subscription`,
		Run: func(cmd *cobra.Command, args []string) {
			subscriptionID, err := cmd.Flags().GetString("subscription-id")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			if subscriptionID == "" {
				errorMessage := "subscription-id is not set"
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			a.AzureConfig.SubID = subscriptionID

			report := iam.EnumerateIAMResources(cmd.Context(), a.AzureConfig)

			a.OutputSignal.Content = report
		},
	}
	enumerateCmd.PersistentFlags().StringP("subscription-id", "s", "", "Azure subscription ID")

	iamCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(iamCmd)
}
