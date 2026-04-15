# tpub-impl cheat sheet

`tpub` maps requested tool arguments into the target names expected by `tbi quick`, then runs the quick installer with an optional target filter.

## files

- `tpub_run_quick_publish`: treats every argument except `-force` as a requested tool, resolves each one into the target list, and runs `tbi quick`.
- `tpub_join_target_list`: converts the resolved target names into the comma-separated string used for `tbi quick --target`.
- `tpub_resolve_rebuild_target`: uses `there --path`, falls back to the literal argument when the tool cannot be resolved into an executable path, and preserves unexpected resolver errors.