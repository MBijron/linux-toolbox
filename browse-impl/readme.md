# browse-impl cheat sheet

`browse` opens URLs or file targets in Google Chrome from WSL.

## files

- `browse_get_chrome_executable_path`: resolves the fixed Chrome path from Windows form to WSL form.
- `browse_validate_executable_exists`: checks that the Chrome executable exists before launch.
- `browse_prepare_argument`: converts local file paths into Windows-friendly paths and leaves URLs/Chrome flags untouched.
- `browse_launch`: starts Chrome in the background and disowns the process.