# Basic Usage

Before you get started, you will need to make Azure credentials available to methodazure as environment variables. The section below covers what it looks for.

## Authentication

methodazure leverages the Microsoft Azure SDK's environment variable mechanism for accessing the appropriate credentials to communicate with Azure resources. Microsoft's developer blog goes into more detail [here](https://devblogs.microsoft.com/azure-sdk/authentication-and-the-azure-sdk/) but essentially if the `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID` environment variables are set, we can leverage the Azure SDK to authenticate.

## Binaries

Running as a binary means you don't need to do anything additional for methodazure to leverage the environment variables you have already exported. You can test that things are working properly by running:

```bash
methodazure vnet enumerate --subscription-id <id> --output json
```

## Docker

Running methodazure within a Docker container requires that you pass the Azure credential environment variables into the container. This can be done with the following command:

```bash
docker run \
  -e AZURE_TENANT_ID=$AZURE_TENANT_ID \
  -e AZURE_CLIENT_ID=$AZURE_CLIENT_ID \
  -e AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET \
  ghcr.io/method-security/methodazure:0.0.1 vnet enumerate --subscription-id <id> --output json
```
