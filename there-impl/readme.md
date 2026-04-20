# there-impl cheat sheet

`there` resolves a PATH wrapper with `where`, reads that wrapper file, and returns the real executable or direct-call template behind it.

## files

- `there_get_first_where_result`: runs `where <tool>` and prints the first result.
- `there_validate_wrapper_file`: ensures the first `where` result is a regular file.
- `there_print_wrapper_content`: prints the wrapper file contents exactly as stored on disk.
- `there_resolve_tool_target_path`: resolves the tool target from a managed toolbox Windows shim or a legacy wrapper with quoted `.exe` paths.
- `there_resolve_tool_executable_path`: prints the resolved tool target path.
- `there_print_tool_call_template`: prints one shell-escaped command line for direct calls, replacing the wrapper's forwarded-arguments slot with `__TB_WRAPPER_ARGS__`.
- `there_get_executable_name`: prints the executable filename without its extension.
- `there_get_executable_version`: classifies the resolved path as `Published`, `Release`, `Debug`, or `Unknown`.