// Package iam provides functions and data structures to interact with Azure IAM resources.
package iam

import (
	"context"

	methodazure "github.com/Method-Security/methodazure/generated/go"
	"github.com/Method-Security/methodazure/internal/config"
)

// EnumerateIAMResources enumerates all IAM related resources in the subscription, returning a report of the resources and
// any non-fatal errors encountered.
func EnumerateIAMResources(ctx context.Context, cfg config.AzureConfig) methodazure.IamReport {
	errors := []string{}

	// Get all roles in the subscription
	roles, err := listRoles(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Get all role assignments in the subscription
	roleAssignments, err := listRoleAssignments(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return methodazure.IamReport{
		SubscriptionId:  cfg.SubID,
		TenantId:        cfg.TenantID,
		RoleDefinitions: roles,
		RoleAssignments: roleAssignments,
		Errors:          errors,
	}
}
