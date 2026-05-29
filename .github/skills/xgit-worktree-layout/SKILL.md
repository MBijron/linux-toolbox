# xgit-worktree-layout

Use this skill when changing `xgit w`, `c` worktree discovery, or any workflow that depends on the on-disk worktree folder layout.

## Layout

- A repo at `<parent>/<repo>` stores its worktrees under `<parent>/.w/<folder-key>`.
- `<folder-key>` uses the ticket prefix from the last branch segment, such as `CUAC-123`, when the branch tail starts with `<letters>-<digits>`.
- If the branch tail has no ticket prefix, `xgit w checkout` generates `LOC-<number>` and uses that as the folder key.
- If a ticket-derived folder key already exists in the same `.w` directory, `xgit w checkout` appends `-2`, `-3`, and so on until the folder key is unique.

## Metadata

- `.w/worktrees.tsv` is the authoritative mapping for that parent directory.
- Each row is tab-separated as `<repo-root> <branch-name> <folder-key>`.
- `xgit w checkout` must add or replace the row for the current repo and branch after a successful `git worktree add`.
- `xgit w remove` must remove the matching metadata row after a successful `git worktree remove`.

## Command behavior

- `xgit w remove <branch>` resolves the target through `.w/worktrees.tsv` for the current repo instead of using the short on-disk folder key.
- `xgit w remove` accepts either the full branch name or an unambiguous last branch segment.
- `c` discovers worktrees by scanning `.w` directories under repo roots and then reading `.w/worktrees.tsv` to recover the branch name and base repo name.
- `c` search must keep matching worktree branch names even though the actual folder names are shortened.
- `c` renders worktrees as the base repo name with a second line that shows the branch name and the short folder key in a distinct color.

## Validation

1. Run `bash -n` and `zsh -n` on every touched shell file.
2. In a temporary repo, create a branch with and without a ticket prefix, run `xgit w checkout`, and confirm the worktree lands under `.w/` with the expected `worktrees.tsv` entry.
3. Run `c --force` from a shell that has toolbox functions loaded and confirm the worktree row shows the branch plus the short folder key.
4. Remove the worktree with `xgit w remove <branch>` and confirm the `.w/worktrees.tsv` row is deleted.
