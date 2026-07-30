# Capabilities

methodazure is being rebuilt. Its previous enumeration commands were retired so that new ones can be written against the current tool conventions, so the CLI currently ships only its root scaffolding — `help`, `completion`, and `version`.

Capability pages will be added back here as each new command lands. The last release containing the retired commands is [v0.0.17](https://github.com/Method-Security/methodazure/releases/tag/v0.0.17).

## Top Level Flags

methodazure has several top level flags that can be used on any subcommand. These include:

```bash
Flags:
  -c, --cloud-config string   Azure Cloud to use (AzurePublic, AzureGovernment, AzureChina) (default "AzurePublic")
  -h, --help                  help for methodazure
  -o, --output string         Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string    Path to output file. If blank, will output to STDOUT
  -q, --quiet                 Suppress output
  -v, --verbose               Verbose output
```

## Version Command

Run `methodazure version` to get the exact version information for your binary

## Output Formats

For more information on the various output formats that are supported by methodazure, see the [Output Formats](https://method-security.github.io/docs/output.html) page in our organization wide documentation.
