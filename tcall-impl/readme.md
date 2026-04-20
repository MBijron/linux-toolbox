# tcall-impl cheat sheet

`tcall` resolves a toolbox wrapper through `there --call` and invokes the underlying tool directly.

## files

- `tcall_run`: reads the single-line `there --call` template, inserts forwarded arguments, and runs the reconstructed command.
- `tcall_convert_forwarded_argument`: converts forwarded path arguments the same way toolbox Windows shims do.
- `tcall_wrapper_uses_argument_conversion`: detects whether a wrapper is a managed toolbox Windows shim and therefore expects converted path arguments.