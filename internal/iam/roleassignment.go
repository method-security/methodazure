// Package iam provides functions and data structures to interact with Azure IAM resources.
package iam

import (
	"context"
	"fmt"

	armpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	methodazure "github.com/Method-Security/methodazure/generated/go"
	"github.com/Method-Security/methodazure/internal/config"
)

func listRoleAssignments(ctx context.Context, cfg config.AzureConfig) ([]*methodazure.RoleAssignment, error) {
	roleAssignments := []*methodazure.RoleAssignment{}

	// Create a new client to interact with the Authorization resource provider
	clientOptions := &armpolicy.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: cfg.CloudConfig,
		},
	}
	clientFactory, err := armauthorization.NewClientFactory(cfg.SubID, cfg.Cred, clientOptions)
	if err != nil {
		return roleAssignments, fmt.Errorf("failed to create client factory: %v", err)
	}

	// The scope for listing role definitions (in this case, the subscription)
	scope := fmt.Sprintf("/subscriptions/%s", cfg.SubID)

	// Create a pager to list all role assignments in the subscription
	pager := clientFactory.NewRoleAssignmentsClient().NewListForScopePager(scope, nil)

	// Loop through the pages and save each role assignment
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return roleAssignments, fmt.Errorf("failed to advance page: %v", err)
		}
		for _, ra := range page.Value {
			roleAssignment := convertRoleAssignment(ra)
			roleAssignments = append(roleAssignments, roleAssignment)
		}
	}

	return roleAssignments, nil
}
