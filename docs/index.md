# methodazure Documentation

Hello and welcome to the methodazure documentation. While we always want to provide the most comprehensive documentation possible, we thought you may find the below sections a helpful place to get started.

- The [Getting Started](./getting-started/basic-usage.md) section provides onboarding material
- The [Development](./development/setup.md) header is the best place to get started on developing on top of and with methodazure
- See the [Docs](./docs/index.md) section for a comprehensive rundown of methodazure capabilities

# About methodazure

methodazure provides security operators with a number of data-rich Azure enumeration capabilities to help them gain visibility into their Azure environments. Designed with data-modeling and data-integration needs in mind, methodazure can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The number of security-relevant Azure resources that methodazure can enumerate are constantly growing. For the most up to date listing, please see the documentation [here](./docs/index.md)

To learn more about methodazure, please see the [Documentation site](https://method-security.github.io/methodazure/) for the most detailed information.

## Quick Start

### Get methodazure

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/methodazure`
- `docker run ghcr.io/method-security/methodazure`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/methodazure/releases/latest) page
- [Installation documentation](./getting-started/installation.md)

### Authentication

methodazure is built using the [Azure SDK for Go](https://github.com/Azure/azure-sdk-for-go) and authenticates with `DefaultAzureCredential`, which walks the standard Azure credential chain — environment variables, workload and managed identity, and a signed-in Azure CLI session. For more information, see Microsoft's [Authentication and the Azure SDK](https://devblogs.microsoft.com/azure-sdk/authentication-and-the-azure-sdk/).

`AZURE_TENANT_ID` must be exported regardless of which link in the chain supplies the credential — methodazure exits with an error if it is unset. To authenticate as a service principal, export the client credentials alongside it:

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
```

Sovereign clouds are selected with `--cloud-config` (`AzurePublic`, `AzureGovernment`, `AzureChina`); it defaults to `AzurePublic`.

### General Usage

```bash
methodazure <resource> enumerate --subscription-id <id>
```

Available resources: `aks`, `database`, `dns`, `entra`, `iam`, `loadbalancer`, `nsg`, `resourcegroup`, `storage`, `subscription`, `tenant`, `vm`, `vnet`.

`subscription` and `tenant` enumerate what the credential can reach, so they take no `--subscription-id`. `entra` queries Microsoft Graph and accepts `--graph-service-endpoint`, which is defaulted from `--cloud-config`.

#### Examples

```bash
methodazure storage enumerate --subscription-id <id>
```

```bash
methodazure vm enumerate --subscription-id <id> --output json
```

```bash
methodazure subscription enumerate
```

## Contributing

Interested in contributing to methodazure? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie methodazure into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

methodazure is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).
