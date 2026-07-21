# lib/vn cheat sheet

`vn` runs extensionless command files from the directory configured by `TB_VIRTUAL_NETWORK_LOCATION`.

## files

- `vn_run`: validates the configured location and command name, then forwards all remaining arguments to the command.
- `vn_print_available_commands`: lists the extensionless files that can be invoked.
