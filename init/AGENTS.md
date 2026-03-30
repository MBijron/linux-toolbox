# Toolbox Init Maintenance Notes

This file records the shell-bootstrap changes made during the March 30, 2026 session so a future agent can restore broken behavior quickly.

## Purpose

The shell startup logic was moved out of the home directory and into `/toolbox/init` so it can be updated by pulling the toolbox repository instead of manually editing per-machine dotfiles.

The current source of truth is:

- `/toolbox/init/.tbirc`
- `/toolbox/init/.zshrc`
- `/toolbox/init/tb_repo_check`
- `/toolbox/init/tb_zcompile_cache`

The home bootstrap file is now:

- `/home/maurice/.zshrc`

The user-specific file `/home/maurice/.tbrc` must remain in the home directory and is still sourced from `/toolbox/init/.zshrc`.

## Boot Flow

Normal fast path:

1. `/home/maurice/.zshrc` sources Fig pre hook.
2. `/home/maurice/.zshrc` checks for `/toolbox/init/.zshrc`.
3. If present, it sources `/toolbox/init/.zshrc` immediately.
4. `/toolbox/init/.zshrc` sources `/toolbox/init/.tbirc`.
5. `/toolbox/init/.tbirc` sources `/toolbox/.env`, schedules repo maintenance in the background, sources `/toolbox/tbr`, runs `tbr`, then runs `toolbox_initialize` if defined.
6. `/toolbox/init/.zshrc` sources `/home/maurice/.tbrc`, loads a lite Oh My Zsh path, loads `zi`, schedules remaining plugins, and sources Fig post hook.

Bootstrap repair path:

1. If `/toolbox/init/.zshrc` or `/toolbox/init/.tbirc` is missing, the home stub attempts to clone or repair `/toolbox` in the same shell.
2. After repair it tries again to source the toolbox init file immediately.

## Major Session Changes

### 1. Initialization logic moved into `/toolbox/init`

Reason:

- Easier maintenance across devices
- Updating `/toolbox` is simpler than hand-maintaining home dotfiles

Important constraint:

- Plugin folders were not relocated
- Home installer assumptions were preserved as much as possible

### 2. Toolbox repo maintenance is async on the normal path

Implemented in `/toolbox/init/.tbirc` and `/toolbox/init/tb_repo_check`.

Behavior:

- Every shell schedules a background repo check
- Startup does not block on repo clone/repair
- Messages are only printed if repo repair or clone is actually needed

If this breaks:

- Check `/toolbox/init/tb_repo_check`
- Check that `git.exe` still exists in `PATH`
- Check `/toolbox/.repo-check.lock`

### 3. `tbr` is cache-first

Implemented in `/toolbox/tbr`.

Behavior:

- `/toolbox/.tbr.cache` is used on startup when available
- Background maintenance refreshes that cache
- `xgit` remains live-sourced because it depends on its original source path

Related background worker:

- `/toolbox/background/_tbr_background`

If toolbox commands disappear or become stale:

- Inspect `/toolbox/.tbr.cache`
- Inspect `/toolbox/.tbr_background.pid`
- Run `source /toolbox/.env && source /toolbox/tbr && tbr --force`

### 4. Full `oh-my-zsh.sh` was replaced with a lite load

Implemented in `/toolbox/init/.zshrc`.

Reason:

- Full OMZ plus `compinit` was one of the main startup bottlenecks

Current lite load keeps:

- `theme-and-appearance.zsh`
- `history.zsh`
- `git.zsh`
- `plugins/git/git.plugin.zsh`
- `themes/robbyrussell.zsh-theme`

This was necessary because full OMZ startup was too slow for the user’s target.

### 5. Completions are lazy

Implemented in `/toolbox/init/.zshrc`.

Behavior:

- Tab is rebound to `__tb_lazy_expand_or_complete`
- First Tab runs `__tb_lazy_completion_init`
- That initializes `compinit`, OMZ completion config, and replays `zi` completions

If completion stops working:

- Inspect `__tb_lazy_completion_init`
- Check that `compinit` is available
- Check `zi cdreplay -q`
- Check `${ZDOTDIR:-$HOME}/.zcompdump-${HOST%%.*}-${ZSH_VERSION}`

### 6. History persistence had to be restored explicitly

Important bug fixed late in the session:

- When full OMZ was removed, shell history stopped persisting between sessions
- Root cause: `history.zsh` was no longer being sourced

Current fix:

- `/toolbox/init/.zshrc` now sources `$ZSH/lib/history.zsh`

Symptoms if this regresses:

- `HISTFILE` empty
- `SAVEHIST=0`
- History appears reset every new shell

Quick validation command:

`zsh -ic 'print HISTFILE=$HISTFILE; print HISTSIZE=$HISTSIZE; print SAVEHIST=$SAVEHIST; setopt | grep history | sort'`

Expected minimums:

- `HISTFILE=/home/maurice/.zsh_history`
- `HISTSIZE=50000`
- `SAVEHIST=10000`
- `extendedhistory`
- `sharehistory`

### 7. Autosuggestions are eager, other zi plugins remain deferred

Reason:

- The deferred `sched +1` zi load does not run before the first prompt sits idle
- That means first-prompt autosuggestions do not appear unless at least one command has already run

Current state:

- `zsh-users/zsh-autosuggestions` is loaded immediately via `zi` during startup
- `fast-syntax-highlighting`, `zsh-completions`, and `agkozak/zsh-z` stay on the deferred path
- Do not reintroduce direct eager sourcing of `~/.zi/plugins/zsh-users---zsh-autosuggestions/...`

## Files Intentionally Left In Home

These were intentionally not moved into `/toolbox` logic or not removed entirely:

- `/home/maurice/.tbrc` stays user-local
- `/home/maurice/.fig/shell/zshrc.pre.zsh`
- `/home/maurice/.fig/shell/zshrc.post.zsh`
- `~/.zi` plugin/install directory remains in the standard home location

## Performance Notes

Performance was improved, but not to the user’s `< 200ms` target.

Known reasons:

- Startup logging is still always enabled
- Fig is still enabled
- `zi` still loads and schedules plugins
- Even the lite OMZ path plus logging still costs nontrivial time

The user explicitly asked to keep:

- startup logging always on
- Fig always enabled

That limits how far startup can be reduced without changing product requirements.

## Things A Future Agent Should Not Do Casually

- Do not relocate plugin folders out of their normal home locations
- Do not add installer requirements outside home dotfiles and `/toolbox`
- Do not remove sourcing of `/home/maurice/.tbrc`
- Do not reintroduce full `source $ZSH/oh-my-zsh.sh` unless the user explicitly accepts the startup cost
- Do not source `.zwc` files directly by path; generate them in the background if useful, but source the original file path

## Fast Recovery Checklist

If shell startup breaks, inspect in this order:

1. `/home/maurice/.zshrc`
2. `/toolbox/init/.zshrc`
3. `/toolbox/init/.tbirc`
4. `/toolbox/tbr`
5. `/toolbox/.tbr.cache`
6. `/toolbox/background/_tbr_background`
7. `/toolbox/init/tb_repo_check`

If history breaks, inspect:

1. `/toolbox/init/.zshrc`
2. `$ZSH/lib/history.zsh`

If completions break, inspect:

1. `__tb_lazy_completion_init` in `/toolbox/init/.zshrc`
2. `compinit`
3. `.zcompdump`
4. `zi cdreplay -q`

If toolbox commands break, inspect:

1. `/toolbox/tbr`
2. `/toolbox/.tbr.cache`
3. `tbr --force`

If bootstrap from home breaks, inspect:

1. `/home/maurice/.zshrc`
2. existence of `/toolbox/init/.zshrc`
3. existence of `/toolbox/init/.tbirc`

## Suggested Future Speedups

If the user asks to continue optimizing startup, the next realistic levers are:

1. Make startup logging opt-in instead of always-on
2. Make Fig optional or terminal-specific
3. Defer more `zi` work until first use
4. Trim the lite OMZ path further
5. Split `/home/maurice/.tbrc` into fast and slow parts if it grows
