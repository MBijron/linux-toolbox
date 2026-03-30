# Toolbox command and function organization

- Keep each root command file (for example `code`, `c`, `call`) as a thin entrypoint.
- Put implementation functions in a sibling `<command>-impl` folder (for example `code-impl`, `c-impl`).
- Every function must live in its own file inside the relevant `<command>-impl` folder.
- Function names and file names must clearly describe what they do.
- If existing names are unclear, rename functions to explicit, readable names.
- Prefer small, simple functions that are easy to read and understand.
- Do not create overly-small functions just to split code; each function should represent a clear, logical unit of behavior.
- You may create subfolders in a `<command>-impl` folder when grouping improves clarity.
- Keep a concise `readme.md` in each `*-impl` folder as a cheat sheet for the layer structure and key files.
- When working in a `*-impl` folder, quickly read that folder's `readme.md` first to understand the implementation layout.
- When changing the structure or responsibilities in a `*-impl` folder, keep its `readme.md` up to date.
- Before changing the initialization flow in `/toolbox/init/.zshrc` or related bootstrap files, read `/toolbox/init/AGENTS.md` first.
- For every `vscode_askQuestions` call, leave freeform input enabled so the user can type a custom response.
- If the user asks for an explanation, deliver it through `vscode_askQuestions`; if the explanation is too long for that dialog, write it to a markdown file in the workspace and use `vscode_askQuestions` to point the user to it.
- Do not add manual `source` steps for these files; loading is handled automatically by rtb/tbr during Linux startup.
- After completing work, always ask for user feedback using the `vscode_askQuestions` tool before ending the conversation.
- Only end the conversation after that feedback request has been sent successfully.
