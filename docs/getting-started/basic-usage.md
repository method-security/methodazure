# Basic Usage

Before you get started, you will need to make Azure credentials available to methodazure as environment variables. The section below covers what it looks for.

## Authentication

methodazure leverages the Microsoft Azure SDK's environment variable mechanism for accessing the appropriate credentials to communicate with Azure resources. Microsoft's developer blog goes into more detail [here](https://devblogs.microsoft.com/azure-sdk/authentication-and-the-azure-sdk/) but essentially if the `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID` environment variables are set, we can leverage the Azure SDK to authenticate.

## Binaries

The `storage external` command performs anonymous probing, so it can run without Azure credentials. Provide either one container URL or one target seed:

```bash
methodazure storage external --url https://account.blob.core.windows.net/container
methodazure storage external --target-seed example.com --max-candidates 100
```

## Docker

The anonymous storage command does not need Azure environment variables:

```bash
docker run ghcr.io/method-security/methodazure:latest \
  storage external --target-seed example.com
```

Pass `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` when using commands that authenticate to Azure APIs.
