export TBDIR="${TBDIR:-/toolbox}"

if [[ -f "$TBDIR/init/.tbirc" ]]; then
  source "$TBDIR/init/.tbirc"
fi

__tb_log "Loading shell configuration"
if typeset -f __tb_source_fast >/dev/null 2>&1; then
  __tb_source_fast "$HOME/.tbrc"
else
  source "$HOME/.tbrc"
fi

export ZSH="/root/.oh-my-zsh"
ZSH_THEME="robbyrussell"
DISABLE_MAGIC_FUNCTIONS="true"
plugins=(git)

__tb_omz_cache_dir() {
  print -r -- "${XDG_CACHE_HOME:-$HOME/.cache}/toolbox/zsh-init"
}

__tb_omz_cache_targets() {
  reply=(
    "$ZSH/lib/theme-and-appearance.zsh|omz/lib/theme-and-appearance.zsh"
    "$ZSH/lib/history.zsh|omz/lib/history.zsh"
    "$ZSH/lib/git.zsh|omz/lib/git.zsh"
    "$ZSH/plugins/git/git.plugin.zsh|omz/plugins/git/git.plugin.zsh"
    "$ZSH/themes/robbyrussell.zsh-theme|omz/themes/robbyrussell.zsh-theme"
  )
}

__tb_omz_file_signature() {
  stat -c '%Y|%s' "$1" 2>/dev/null
}

__tb_load_omz_cache_map() {
  local cache_dir manifest_path bundle_id line payload source_path rel_path cache_path current_signature
  local expected_signature
  local -a targets
  local -A manifest_rel_paths manifest_signatures

  cache_dir="$(__tb_omz_cache_dir)"
  manifest_path="$cache_dir/manifest"
  [[ -f "$manifest_path" ]] || return 1

  typeset -gA __tb_omz_cached_sources
  __tb_omz_cached_sources=()

  while IFS= read -r line; do
    case "$line" in
      bundle=*)
        bundle_id="${line#bundle=}"
        ;;
      entry=*)
        payload="${line#entry=}"
        source_path="${payload%%|*}"
        payload="${payload#*|}"
        rel_path="${payload%%|*}"
        payload="${payload#*|}"
        manifest_rel_paths[$source_path]="$rel_path"
        manifest_signatures[$source_path]="$payload"
        ;;
    esac
  done < "$manifest_path"

  [[ -n "$bundle_id" ]] || return 1

  __tb_omz_cache_targets
  targets=("${reply[@]}")

  for payload in "${targets[@]}"; do
    source_path="${payload%%|*}"
    rel_path="${payload#*|}"
    [[ "${manifest_rel_paths[$source_path]:-}" == "$rel_path" ]] || return 1

    cache_path="$cache_dir/bundles/$bundle_id/$rel_path"
    [[ -f "$cache_path" ]] || return 1

    expected_signature="${manifest_signatures[$source_path]:-}"
    current_signature="$(__tb_omz_file_signature "$source_path")"
    [[ -n "$current_signature" && "$current_signature" == "$expected_signature" ]] || return 1

    __tb_omz_cached_sources[$source_path]="$cache_path"
  done

  return 0
}

__tb_resolve_omz_source() {
  local source_path="$1"

  print -r -- "${__tb_omz_cached_sources[$source_path]:-$source_path}"
}

__tb_refresh_omz_cache_async() {
  local helper_path="$TBDIR/init/tb_refresh_omz_cache"
  local shell_path cache_dir lock_dir
  local -a targets

  [[ -f "$helper_path" ]] || return 0

  cache_dir="$(__tb_omz_cache_dir)"
  lock_dir="$cache_dir/refresh.lock"

  command mkdir -p "$cache_dir" 2>/dev/null || return 0
  command mkdir "$lock_dir" 2>/dev/null || return 0

  shell_path="$(command -v zsh)"
  if [[ -z "$shell_path" ]]; then
    rmdir "$lock_dir" 2>/dev/null || true
    return 0
  fi

  __tb_omz_cache_targets
  targets=("${reply[@]}")

  if [[ -n "$ZSH_VERSION" ]]; then
    TB_STARTUP_CACHE_DIR="$cache_dir" TB_STARTUP_CACHE_LOCK_DIR="$lock_dir" \
      nohup "$shell_path" "$helper_path" "${targets[@]}" >/dev/null 2>&1 &!
  else
    TB_STARTUP_CACHE_DIR="$cache_dir" TB_STARTUP_CACHE_LOCK_DIR="$lock_dir" \
      nohup "$shell_path" "$helper_path" "${targets[@]}" >/dev/null 2>&1 &
    disown $! 2>/dev/null || true
  fi
}

__tb_prepare_omz_cache() {
  __tb_load_omz_cache_map && return 0
  __tb_refresh_omz_cache_async
  return 1
}

__tb_omz_lite_load() {
  local theme_appearance_path history_path git_lib_path git_plugin_path theme_path

  autoload -Uz colors
  colors

  export ZSH_CACHE_DIR="${ZSH_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/oh-my-zsh}"

  if ! (( ${+functions[compdef]} )); then
    compdef() { :; }
  fi

  theme_appearance_path="$(__tb_resolve_omz_source "$ZSH/lib/theme-and-appearance.zsh")"
  history_path="$(__tb_resolve_omz_source "$ZSH/lib/history.zsh")"
  git_lib_path="$(__tb_resolve_omz_source "$ZSH/lib/git.zsh")"
  git_plugin_path="$(__tb_resolve_omz_source "$ZSH/plugins/git/git.plugin.zsh")"
  theme_path="$(__tb_resolve_omz_source "$ZSH/themes/robbyrussell.zsh-theme")"

  source "$theme_appearance_path"
  source "$history_path"
  source "$git_lib_path"
  source "$git_plugin_path"
  source "$theme_path"
}

__tb_load_zi_autosuggestions() {
  if [[ "${__tb_zi_autosuggestions_loaded:-0}" == "1" ]]; then
    return 0
  fi

  __tb_zi_autosuggestions_loaded="1"

  zi ice silent
  zi light zsh-users/zsh-autosuggestions
}

__tb_zcompile_targets() {
  reply=(
    "$HOME/.zshrc"
    "$HOME/.tbrc"
    "$TBDIR/init/.tbirc"
    "$TBDIR/init/.zshrc"
    "$TBDIR/tbr"
    "$TBDIR/.tbr.cache"
    "$HOME/.zi/bin/zi.zsh"
  )
}

__tb_file_needs_zcompile() {
  local file="$1"
  local zwc_path="${file}.zwc"
  local zwc_dir="${zwc_path%/*}"

  [[ -f "$file" ]] || return 1
  if [[ -f "$zwc_path" ]]; then
    [[ -w "$zwc_path" ]] || return 1
  else
    [[ -d "$zwc_dir" && -w "$zwc_dir" ]] || return 1
  fi

  [[ ! -f "${file}.zwc" || "$file" -nt "${file}.zwc" ]]
}

__tb_any_zcompile_target_stale() {
  local file
  local -a targets

  __tb_zcompile_targets
  targets=("${reply[@]}")

  for file in "${targets[@]}"; do
    if __tb_file_needs_zcompile "$file"; then
      return 0
    fi
  done

  return 1
}

__tb_load_zi_deferred_plugins() {
  if [[ "${__tb_zi_deferred_plugins_loaded:-0}" == "1" ]]; then
    return 0
  fi

  __tb_zi_deferred_plugins_loaded="1"

  zi ice wait'0' silent
  zi light zdharma/fast-syntax-highlighting
  zi ice wait'0' silent
  zi light zsh-users/zsh-completions
  zi ice wait'0' silent
  zi light agkozak/zsh-z
}

__tb_lazy_completion_init() {
  if [[ "${__tb_completions_loaded:-0}" == "1" ]]; then
    return 0
  fi

  __tb_completions_loaded="1"

  __tb_load_zi_deferred_plugins

  mkdir -p "$ZSH_CACHE_DIR/completions"
  unfunction compdef 2>/dev/null || true
  autoload -Uz compinit
  compinit -d "${ZDOTDIR:-$HOME}/.zcompdump-${HOST%%.*}-${ZSH_VERSION}"

  source "$ZSH/lib/completion.zsh"
  source "$ZSH/plugins/git/git.plugin.zsh"

  if (( ${+functions[_zi]} )) && (( ${+_comps} )); then
    _comps[zi]=_zi
  fi

  if typeset -f zi >/dev/null 2>&1; then
    zi cdreplay -q >/dev/null 2>&1 || true
  fi

  bindkey '^I' expand-or-complete
  bindkey -M emacs '^I' expand-or-complete
  bindkey -M viins '^I' expand-or-complete
  bindkey -M vicmd '^I' expand-or-complete
}

__tb_lazy_expand_or_complete() {
  __tb_lazy_completion_init || return
  zle expand-or-complete
}

__tb_cancel_prompt_input() {
  BUFFER=""
  CURSOR=0
  zle -I
  zle reset-prompt
}

__tb_prepare_omz_cache
__tb_omz_lite_load

zle -N __tb_lazy_expand_or_complete
zle -N __tb_cancel_prompt_input
bindkey '^I' __tb_lazy_expand_or_complete
bindkey -M emacs '^I' __tb_lazy_expand_or_complete
bindkey -M viins '^I' __tb_lazy_expand_or_complete
bindkey -M vicmd '^I' __tb_lazy_expand_or_complete

TRAPINT() {
  if zle; then
    zle __tb_cancel_prompt_input
    return 0
  fi

  return 130
}

# User configuration

__tb_base_prompt="%(?:%{$fg[green]%}➜ :%{$fg[red]%}➜ ) %{$fg[cyan]%}%2c%{$reset_color%} "
PROMPT="$__tb_base_prompt"
__tb_prompt_boot_time_pending="1"

__tb_set_prompt_with_boot_time() {
  local now boot_ms

  if [[ "${__tb_prompt_boot_time_pending:-0}" == "1" ]]; then
    now="$(__tb_now_ms)"
    boot_ms=$((now - __tb_start_ms))
    __tb_log "Prompt ready in ${boot_ms}ms"
    PROMPT="%{$fg[yellow]%}[boottime: ${boot_ms}ms]%{$reset_color%} ${__tb_base_prompt}"
    __tb_prompt_boot_time_pending="0"
    return 0
  fi

  PROMPT="$__tb_base_prompt"
}

if (( ${precmd_functions[(Ie)__tb_set_prompt_with_boot_time]} == 0 )); then
  precmd_functions=(__tb_set_prompt_with_boot_time ${precmd_functions[@]})
fi

DEFAULT_USER = "maurice" + prompt_context(){}


SPACESHIP_PROMPT_ORDER=(
  user
  dir
  host
  git
  hg
  exec_time
  line_sep
  vi_mode
  jobs
  exit_code
  char
)
SPACESHIP_USER_SHOW=always
SPACESHIP_PROMPT_ADD_NEWLINE=false
SPACESHIP_CHAR_SYMBOL="❯"
SPACESHIP_CHAR_SUFFIX=" "

__tb_log "Loading shell plugins"
if [[ ! -f $HOME/.zi/bin/zi.zsh ]]; then
  __tb_log_notice "Installing z-shell/zi"
  command mkdir -p "$HOME/.zi" && command chmod go-rwX "$HOME/.zi"
  command git clone -q --depth=1 --branch "main" https://github.com/z-shell/zi "$HOME/.zi/bin" && \
    __tb_log_notice "Installation successful" || \
    __tb_log_warning "The clone has failed"
fi
source "$HOME/.zi/bin/zi.zsh"
autoload -Uz _zi
(( ${+_comps} )) && _comps[zi]=_zi

__tb_load_zi_autosuggestions

__tb_zcompile_async() {
  local helper_path="$TBDIR/init/tb_zcompile_cache"
  local shell_path
  local -a targets

  [[ -f "$helper_path" ]] || return 0
  __tb_any_zcompile_target_stale || return 0

  shell_path="$(command -v zsh)"
  [[ -n "$shell_path" ]] || return 0

  __tb_zcompile_targets
  targets=("${reply[@]}")

  if [[ -n "$ZSH_VERSION" ]]; then
    nohup "$shell_path" "$helper_path" "${targets[@]}" >/dev/null 2>&1 &!
  else
    nohup "$shell_path" "$helper_path" "${targets[@]}" >/dev/null 2>&1 &
    disown $! 2>/dev/null || true
  fi
}

zmodload zsh/sched >/dev/null 2>&1 || true
if whence -w sched >/dev/null 2>&1; then
  sched +1 __tb_load_zi_deferred_plugins >/dev/null 2>&1 || __tb_load_zi_deferred_plugins
else
  __tb_load_zi_deferred_plugins
fi

__tb_zcompile_async

[[ -f "$HOME/.fig/shell/zshrc.post.zsh" ]] && builtin source "$HOME/.fig/shell/zshrc.post.zsh"

# __tb_clear