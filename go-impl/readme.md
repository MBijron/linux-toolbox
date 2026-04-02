# go-impl cheat sheet

`go` opens the current repository's `origin` remote in Chrome, or resolves another repository with `c`-style matching first.

## files

- `go_resolve_repository_path`: resolves a repo query with the same filters and selection flow as `c`.
- `go_prepare_path_for_git_command`: converts repo paths into a form the active `git` implementation accepts.
- `go_get_repository_root`: finds the git top-level for the selected path.
- `go_get_origin_remote_url`: reads the `origin` remote URL from the repository.
- `go_convert_remote_url_to_browser_url`: converts SSH and other git remote formats into browser-openable HTTP(S) URLs.