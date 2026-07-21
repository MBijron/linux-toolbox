# lib/tsync cheat sheet

`tsync` refreshes the toolbox installer state, then recreates toolbox applications and shortcuts.

## files

- `tsync_run`: validates arguments, runs `tbi pull -r`, and only if that succeeds runs `tbi quick`.
