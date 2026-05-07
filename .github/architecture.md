# Toolbox Architecture

## Command layout

- Root command files in `/toolbox` stay thin and delegate to helper functions loaded at shell startup.
- Most command logic lives in sibling `*-impl` folders, with one function per file.
- `xgit` is a dispatcher command that discovers aliases from `/toolbox/xgit_bin/git_*` files and invokes the matching `git_*` function.

## Repository navigation

- `c` is the repository chooser. It builds a top-level directory map from configured roots in `c-impl/discovery/` and enriches it with hard-coded entries.
- `c-impl/models/c_repo_map_entry_create` normalizes each discovered folder into a display name and abbreviation.
- `c-impl/text/c_abbreviate` generates abbreviations from folder names and treats dots like other word separators.
- `xgit_bin/git_worktree` now creates worktrees under sibling container folders named `<repo>.worktrees/<branch-tail>`, using only the last branch path segment for the worktree directory name.
- `c-impl/text/c_worktree_entry_metadata` detects both legacy `.worktree.*` folders and the current flat `<repo>.worktrees/<branch-tail>` layout, derives special shortcuts such as `c9666` from ticket prefixes like `CUAC-9666`, and falls back to a truncated regular abbreviation for non-ticket worktree branches.
- `c-impl/models/c_repo_map_entry_create` stores the base repo name for worktree rows so `c` shows the repository name instead of the full worktree path.
- `c-impl/models/c_repo_map_entry_sort_by_modified_time` places worktrees after normal repos and still keeps `archive` entries last.
- `c-impl/presentation/c_print_repo_map` and `c-impl/navigation/c_choose_path` render worktree entries with a dim yellow `[w]` badge and show the ticket suffix in dim text under the repository name.
- `c` persists its repo map in a versioned cache file so representation changes like the worktree display rewrite do not keep serving stale rows from older cache formats.
- `c-impl/cache/c_read_repo_map_cache` rebuilds that cache on demand when the current versioned cache file does not exist, is empty, or is older than the active `c` implementation files, so display and sort changes take effect without manual cache cleanup.
- `c --force` forces a repo-map rebuild before continuing with normal listing or lookup behavior.

## Git helpers

- `xgit_bin/` contains alias-addressable Git helpers such as branch switching and worktree management.
- `xgit_bin/git_worktree` provides `xgit w checkout` and `xgit w remove`, creating sibling worktrees beside the main repository with the naming pattern `<repo>.worktree.<branch>`.
- `xgit_bin/git_worktree` prefers the native Linux `git` binary for worktree operations so Windows-mounted repositories do not hit `git.exe` path-length limits during checkout.
- `xgit_bin/git_worktree` refreshes the `c` repo-map cache after successful add/remove operations so new worktrees are immediately searchable.
- When a helper must fall back to `git.exe` for a path argument on `/mnt/*`, it should convert the WSL path before invoking Git.