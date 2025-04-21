package iam

import (
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	methodazure "github.com/Method-Security/methodazure/generated/go"
	"github.com/Method-Security/methodazure/internal/azure"
)

func convertPermission(azurePermission *armauthorization.Permission) *methodazure.Permission {
	if azurePermission == nil {
		return &methodazure.Permission{}
	}

	var actions []string
	for _, action := range azurePermission.Actions {
		actions = append(actions, *action)
	}
	var notActions []string
	for _, na := range azurePermission.NotActions {
		notActions = append(notActions, *na)
	}
	var dataActions []string
	for _, da := range azurePermission.DataActions {
		dataActions = append(dataActions, *da)
	}
	var notDataActions []string
	for _, nda := range azurePermission.NotDataActions {
		notDataActions = append(notDataActions, *nda)
	}

	return &methodazure.Permission{
		Actions:        actions,
		NotActions:     notActions,
		DataActions:    dataActions,
		NotDataActions: notDataActions,
	}
}

func convertRoleDefinition(azureRoleDefinition *armauthorization.RoleDefinition) *methodazure.RoleDefinition {
	if azureRoleDefinition == nil {
		return &methodazure.RoleDefinition{}
	}

	var assignableScopes []string
	for _, as := range azureRoleDefinition.Properties.AssignableScopes {
		assignableScopes = append(assignableScopes, *as)
	}
	var permissions []*methodazure.Permission
	for _, p := range azureRoleDefinition.Properties.Permissions {
		permissions = append(permissions, convertPermission(p))
	}

	roleDefinition := &methodazure.RoleDefinition{
		Id:               azure.GetStringPtrValue(azureRoleDefinition.ID),
		Name:             azure.GetStringPtrValue(azureRoleDefinition.Name),
		Type:             azure.GetStringPtrValue(azureRoleDefinition.Type),
		AssignableScopes: assignableScopes,
		Description:      azureRoleDefinition.Properties.Description,
		RoleName:         azureRoleDefinition.Properties.RoleName,
		RoleType:         azureRoleDefinition.Properties.RoleType,
		Permissions:      permissions,
	}

	return roleDefinition
}

func convertRoleAssignment(azureRoleAssignment *armauthorization.RoleAssignment) *methodazure.RoleAssignment {
	if azureRoleAssignment == nil {
		return &methodazure.RoleAssignment{}
	}

	roleAssignment := &methodazure.RoleAssignment{
		Id:                                 azure.GetStringPtrValue(azureRoleAssignment.ID),
		Name:                               azure.GetStringPtrValue(azureRoleAssignment.Name),
		Type:                               azure.GetStringPtrValue(azureRoleAssignment.Type),
		PrincipalId:                        azure.GetStringPtrValue(azureRoleAssignment.Properties.PrincipalID),
		RoleDefinitionId:                   azure.GetStringPtrValue(azureRoleAssignment.Properties.RoleDefinitionID),
		Condition:                          azureRoleAssignment.Properties.Condition,
		ConditionVersion:                   azureRoleAssignment.Properties.ConditionVersion,
		DelegatedManagedIdentityResourceId: azureRoleAssignment.Properties.DelegatedManagedIdentityResourceID,
		Description:                        azureRoleAssignment.Properties.Description,
		CreatedBy:                          azureRoleAssignment.Properties.CreatedBy,
		CreatedOn:                          azureRoleAssignment.Properties.CreatedOn,
		Scope:                              azureRoleAssignment.Properties.Scope,
		UpdatedBy:                          azureRoleAssignment.Properties.UpdatedBy,
		UpdatedOn:                          azureRoleAssignment.Properties.UpdatedOn,
	}

	principalType, err := methodazure.NewPrincipalTypeFromString(azure.GetStringEnumPtrValue(azureRoleAssignment.Properties.PrincipalType))
	if err != nil && principalType != "" {
		roleAssignment.PrincipalType = &principalType
	}

	return roleAssignment
}
