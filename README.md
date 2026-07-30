<div align="center">
<h1>methodazure</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![Acceptable Use Policy][acceptable-use-policy-img]][acceptable-use-policy]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

methodazure provides security operators with data-rich Azure enumeration capabilities to help them gain visibility into their Azure environments. Designed with data-modeling and data-integration needs in mind, methodazure can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

> **methodazure is being rebuilt.** Its previous enumeration commands were retired so that new ones can be written against the current tool conventions. The CLI currently ships only its root scaffolding — `help`, `completion`, and `version` — and capabilities are being added back one at a time. The last release containing the retired commands is [v0.0.17](https://github.com/Method-Security/methodazure/releases/tag/v0.0.17).

For the most up to date listing of what the tool can enumerate, please see the documentation [here](./docs/index.md)

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

No enumeration commands ship today — see the note above. The root scaffolding is in place, so the CLI responds to:

```bash
methodazure --help
methodazure version
methodazure completion <bash|zsh|fish|powershell>
```

Authentication is only required once a command actually talks to Azure; `help`, `completion`, and `version` run without credentials.

## Contributing

Interested in contributing to methodazure? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie methodazure into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

methodazure is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).

[verify]: https://github.com/Method-Security/methodazure/actions/workflows/verify.yml
[verify-img]: https://github.com/Method-Security/methodazure/actions/workflows/verify.yml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/Method-Security/methodazure
[go-report-img]: https://goreportcard.com/badge/github.com/Method-Security/methodazure
[release]: https://github.com/Method-Security/methodazure/releases
[releases]: https://github.com/Method-Security/methodazure/releases/latest
[release-img]: https://img.shields.io/github/release/Method-Security/methodazure.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/Method-Security/methodazure/total?logo=github
[docker-pulls-img]: https://img.shields.io/docker/pulls/methodsecurity/methodazure?logo=docker&label=docker%20pulls%20%2F%20methodazure
[docker-pull]: https://hub.docker.com/r/methodsecurity/methodazure
[license]: https://github.com/Method-Security/methodazure/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[acceptable-use-policy]: https://github.com/Method-Security/methodazure/blob/main/ACCEPTABLE_USE_POLICY.md
[acceptable-use-policy-img]: https://img.shields.io/badge/acceptable_use-policy-blue
