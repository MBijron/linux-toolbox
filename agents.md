# Toolbox repository instructions

## Command structure

- Keep each root command file, such as `code`, `c`, or `vn`, as a thin entrypoint.
- Put command implementations in `lib/<command>` without an `-impl` suffix.
- Give every function its own extensionless file in the relevant `lib/<command>` directory.
- Use clear, descriptive names for functions and their files.
- Prefer small functions that each represent a complete logical responsibility.
- Add subdirectories below `lib/<command>` only when they make a larger implementation easier to navigate.

## Documentation

- Keep the repository architecture guide at `docs/architecture.md`.
- Keep a concise `readme.md` in each `lib/<command>` directory as a guide to its responsibilities and key files.
- Read the relevant `lib/<command>/readme.md` before changing that implementation.
- Update the local readme when a command's structure or responsibilities change.

## Initialization

- Read `init/AGENTS.md` before changing `init/.zshrc` or related bootstrap files.
- Do not add manual `source` steps for command or implementation files; `tbr` loads extensionless files automatically during shell startup.
