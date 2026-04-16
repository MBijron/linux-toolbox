# code-impl

- `code_print_help`: prints the `code` command help text.
- `code_get_global_instructions_target`: returns the Windows path used by `code -i`.
- `code_get_insiders_executable_path`, `code_validate_executable_exists`: locate and verify the VS Code Insiders executable.
- `code_convert_*`, `code_build_*`, `code_choose_uri_flag_for_target`: convert targets and build the right URI or path for the launch mode.
- `code_launch_*`: start VS Code Insiders in the background with raw arguments, a Windows path, or a remote URI.