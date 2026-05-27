# windows-path-cache

Use this skill when a toolbox shell loses Windows wrapper commands such as `winwhere`, `call`, or other `include_windows_command` shims after startup.

## Symptoms

- `command -v winwhere` fails even though `/toolbox/bin/winwhere` exists.
- A shell starts without `/toolbox/bin` in `PATH`.
- `core/windows_path.startup.cache` was generated from a reduced shell and later removed toolbox paths from startup.

## Invariants

- `core/windows_path.cache` should store only cached Windows PATH entries.
- `core/windows_path.startup.cache` must merge those cached Windows entries into the live shell `PATH`.
- Startup must never replace `PATH` with the cached Windows snapshot, because that can drop `/toolbox/bin` and user-local entries.

## Repair flow

1. Rebuild the toolbox function cache with `source /toolbox/.env && source /toolbox/tbr && tbr --force`.
2. Refresh the Windows path cache with `__tb_windows_path_refresh_cache` after the toolbox helpers are loaded.
3. Validate bootstrap behavior in a clean shell with `HOME=$HOME TBDIR=/toolbox zsh -fc 'source /toolbox/init/.tbirc >/dev/null 2>&1; command -v winwhere >/dev/null && printf ok\\n; printf "%s\\n" "$PATH" | tr ":" "\\n" | grep -x "/toolbox/bin"'`.

## Validation target

- The bootstrap shell should report `winwhere` as available.
- `/toolbox/bin` should still be present in `PATH` after `toolbox_initialize` applies the Windows path cache.