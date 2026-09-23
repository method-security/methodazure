# Storage

The `methodazure storage` command audits Azure Blob Storage services.

## External

`storage external` anonymously probes public-facing containers. Provide exactly one of `--url` or `--target-seed`; Azure credentials are not required.

```bash
# Probe a known container
methodazure storage external \
  --url https://account.blob.core.windows.net/container

# Generate and probe storage account candidates
methodazure storage external \
  --target-seed example.com \
  --max-candidates 100
```

The `--max-candidates` value defaults to 50 and is capped at 500. Use `--cloud-config` to select `AzurePublic`, `AzureGovernment`, or `AzureChina` when generating endpoint URLs.

```bash
methodazure storage external --help
```
