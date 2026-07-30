# Adding a new capability

By design, methodazure breaks every unique Azure resource into its own top level command:

```
methodazure <resource> <verb> [flags]
```

This mirrors [methodaws](https://github.com/Method-Security/methodaws/tree/develop/cmd), the sibling CLI for AWS. The per-cloud tools organise by service because that is how the provider's own surface is organised; the per-domain tools (`networkscan`, `webscan`, `osintscan`) use attack-stage commands instead. methodazure follows the per-cloud shape.

If you are looking to add a brand new capability to the tool, you can take the following steps.

1. Add a file to `cmd/` that corresponds to the sub-command name you'd like to add to the `methodazure` CLI
2. methodazure ships no commands today, so there is no in-repo template. Use [methodaws](https://github.com/Method-Security/methodaws/tree/develop/cmd) for the current shape; the retired methodazure commands are still readable at [v0.0.17](https://github.com/Method-Security/methodazure/tree/v0.0.17/cmd)
3. Your file needs to be a member function of the `methodazure` struct and should be of the form `Init<cmd>Command`
4. Add a new member to the `methodazure` struct in `cmd/root.go` that corresponsds to your command name. Remember, the first letter must be capitalized.
5. Call your `Init` function from `main.go`
6. Add logic to your commands runtime and put it in its own package within `internal` (e.g., `internal/storage`)
7. Define the command's Fern types in `fern/definition/<resource>.yml` and run `./godelw verify` before opening a PR

The root command already supplies `--cloud-config`, `--output`, `--output-file`, `--quiet`, and `--verbose`, along with an authenticated `AzureConfig` on the struct — don't redeclare those.
