# c-impl cheat sheet

`c` is split by responsibility. Start here before changing files.

## layers

- `cache/`: reads and writes the persisted repo-map file.
- `discovery/`: builds the repo list and discovers mounts and scan roots.
- `filtering/`: narrows repo-map rows from exact and fuzzy queries.
- `models/`: shared repo-entry shaping and sort rules.
- `navigation/`: handles match selection and `cd`/`code`/`vs` actions.
- `presentation/`: prints the repo list for humans.
- `text/`: small string helpers.

## files

- `cache/c_cache_path`: returns the versioned root cache file path.
- `cache/c_capture_repo_map_root_state`: snapshots repo-root mtimes for cheap cache dirty checks.
- `cache/c_read_repo_map_cache`: prints cached repo-map rows and rebuilds the cache when the versioned cache file is missing, empty, or older than the active `c` implementation files.
- `cache/c_update_repo_map_cache`: rebuilds the versioned `c` cache atomically for `c --update-cache`.
- `discovery/c_build_repo_map`: main repo-map pipeline, including immediate worktree discovery inside flat `<repo>.worktrees` containers.
- `discovery/c_build_repo_map_enrich`: appends hard-coded entries like `/toolbox`.
- `discovery/c_expand_repo_map_roots`: expands `/mnt/c/...` templates across eligible mounts.
- `discovery/c_list_repo_map_roots`: lists the expanded root folders scanned for repos.
- `discovery/c_list_local_mnt_mounts`: lists `/mnt/*` mounts, excluding `wsl`, `wslg`, and detected network mounts.
- `discovery/c_is_network_mount`: detects remote mounts from `/proc/mounts`.
- `models/c_repo_map_entry_create`: normalizes repo rows, including `_archive` -> `archive` with shortcut `_`, and collapses worktree display names back to the base repo name while keeping special worktree shortcuts.
- `models/c_repo_map_entry_sort_by_modified_time`: sorts rows by modified time, keeps worktrees below normal repos, and keeps `archive` entries last.
- `filtering/c_filter_by_abbreviation`: exact shortcut match.
- `filtering/c_filter_by_abbreviation_text`: partial shortcut match.
- `filtering/c_filter_by_folder_text`: partial folder-name match.
- `navigation/c_find_and_cd`: search flow entrypoint after arg parsing.
- `navigation/c_choose_path`: selects a repo path from c results, including interactive disambiguation.
- `navigation/c_choose_and_cd`: multi-match prompt and destination action.
- `presentation/c_print_repo_map`: colored repo list output, including worktree badges and ticket suffix lines.
- `text/c_abbreviate`: builds shortcuts from folder names.
- `text/c_worktree_entry_metadata`: extracts worktree branch subtitles, base repo names, and special shortcuts like `c9666` from both legacy `.worktree.*` folders and the current flat `<repo>.worktrees/<branch-tail>` layout.