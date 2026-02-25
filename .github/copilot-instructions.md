# Toolbox command and function organization

- Keep each root command file (for example `code`, `c`, `call`) as a thin entrypoint.
- Put implementation functions in a sibling `<command>-impl` folder (for example `code-impl`, `c-impl`).
- Every function must live in its own file inside the relevant `<command>-impl` folder.
- Function names and file names must clearly describe what they do.
- If existing names are unclear, rename functions to explicit, readable names.
- Prefer small, simple functions that are easy to read and understand.
- Do not create overly-small functions just to split code; each function should represent a clear, logical unit of behavior.
- You may create subfolders in a `<command>-impl` folder when grouping improves clarity.
- Do not add manual `source` steps for these files; loading is handled automatically by rtb/tbr during Linux startup.
