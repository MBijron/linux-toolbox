# Toolbox Architecture

## Command layout

- Root command files in `/toolbox` stay thin and delegate to helper functions loaded at shell startup.
- Most command logic lives under the shared `lib/<command>` root, with one function per extensionless file.
- `xgit` is a dispatcher command that discovers aliases from `/toolbox/xgit_bin/git_*` files and invokes the matching `git_*` function.

## Repository navigation

- `c` is the repository chooser. It builds a top-level directory map from configured roots in `lib/c/discovery/` and enriches it with hard-coded entries.
- `c` also reserves the exact queries `local` and `repos` to jump straight to `/mnt/*/localrepo` and `/mnt/*/repos`; when the folder does not exist on any eligible `/mnt/*` drive, it reuses the local-drive discovery rules to prompt for a drive, creates the folder, and then opens it.
- `lib/c/models/c_repo_map_entry_create` normalizes each discovered folder into a display name and abbreviation.
- `lib/c/text/c_abbreviate` generates abbreviations from folder names and treats dots like other word separators.
- `xgit_bin/git_worktree` creates worktrees under a sibling `.w/<folder-key>` directory beside the main repo, where the folder key is the ticket prefix from the last branch segment such as `CUAC-123` when present, otherwise a generated `LOC-<number>` value.
- `xgit_bin/git_worktree` keeps `.w/worktrees.tsv` as the authoritative repo/branch/folder mapping for that parent directory; `c` uses it to recover the real branch name and base repo name while the on-disk folder stays short.
- `lib/c/text/c_worktree_entry_metadata` reads `.w/worktrees.tsv`, derives special shortcuts such as `c9666` from branch ticket prefixes like `CUAC-9666`, and falls back to a truncated regular abbreviation for non-ticket worktree branches.
- `lib/c/models/c_repo_map_entry_create` stores the base repo name for worktree rows so `c` shows the repository name instead of the full worktree path.
- `lib/c/models/c_repo_map_entry_sort_by_modified_time` places worktrees after normal repos and still keeps `archive` entries last.
- `lib/c/presentation/c_print_repo_map_rows` is the shared row renderer used by both `lib/c/presentation/c_print_repo_map` and `lib/c/navigation/c_choose_path`, so the numbered disambiguation list matches the normal `c` output apart from its colored numeric prefix.
- `c` persists its repo map in a versioned cache file so representation changes like the worktree display rewrite do not keep serving stale rows from older cache formats.
- `lib/c/cache/c_read_repo_map_cache` rebuilds that cache on demand when the current versioned cache file does not exist, is empty, or is older than the active `c` implementation files, so display and sort changes take effect without manual cache cleanup.
- `c --force` forces a repo-map rebuild before continuing with normal listing or lookup behavior.

## Git helpers

- `xgit_bin/` contains alias-addressable Git helpers such as branch switching and worktree management.
- `xgit_bin/git_worktree` provides `xgit w checkout` and `xgit w remove`, creating sibling worktrees beside the main repository under `.w/<folder-key>` and resolving removals by branch name instead of the short on-disk folder name.
- `xgit_bin/git_worktree` accepts both local branches and origin-only branches for `xgit w checkout`; when only `origin/<branch>` exists, it creates a local tracking branch directly in the new worktree.
- `xgit_bin/git_worktree` also accepts `xgit w checkout -b <source-branch> <new-branch>` for new worktrees and, when only `xgit w checkout -b <new-branch>` is given, it automatically bases the new branch on the first available branch from `origin/develop`, `origin/master`, then `origin/main`; the create-branch path intentionally ignores local base branches so new worktrees start from the remote tip.
- `xgit_bin/git_worktree` resolves `xgit w remove <branch>` through `.w/worktrees.tsv` for the current repo, accepts either the full branch name or an unambiguous last path segment, and then applies the existing dirty/unpushed safety checks before the confirmed `git worktree remove --force` cleanup.
- `xgit_bin/git_worktree` prefers the native Linux `git` binary for worktree operations so Windows-mounted repositories do not hit `git.exe` path-length limits during checkout.
- `xgit_bin/git_worktree` refreshes the `c` repo-map cache after successful add/remove operations so new worktrees are immediately searchable.
- `xgit_bin/git_worktree` finishes successful `xgit w checkout` runs by replacing `<worktree>/src/.vs` with a copy of `<main-repo>/src/.vs` when that source folder exists, and prints the sync source and destination paths clearly in the terminal.
- When a helper must fall back to `git.exe` for a path argument on `/mnt/*`, it should convert the WSL path before invoking Git.
