export TBDIR="${TBDIR:-/toolbox}"

if [[ -f "$TBDIR/init/.tbirc" ]]; then
  source "$TBDIR/init/.tbirc"
fi

__tb_log "Sourcing ~/.tbrc"
if typeset -f __tb_source_fast >/dev/null 2>&1; then
  __tb_source_fast "$HOME/.tbrc"
else
  source "$HOME/.tbrc"
fi

export ZSH="/root/.oh-my-zsh"
ZSH_THEME="robbyrussell"
DISABLE_MAGIC_FUNCTIONS="true"
plugins=(git)

__tb_omz_lite_load() {
  autoload -Uz colors
  colors

  export ZSH_CACHE_DIR="${ZSH_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/oh-my-zsh}"

  if ! (( ${+functions[compdef]} )); then
    compdef() { :; }
  fi

  source "$ZSH/lib/theme-and-appearance.zsh"
  source "$ZSH/lib/history.zsh"
  source "$ZSH/lib/git.zsh"
  source "$ZSH/plugins/git/git.plugin.zsh"
  source "$ZSH/themes/robbyrussell.zsh-theme"
}

__tb_load_zi_autosuggestions() {
  if [[ "${__tb_zi_autosuggestions_loaded:-0}" == "1" ]]; then
    return 0
  fi

  __tb_zi_autosuggestions_loaded="1"

  zi ice silent
  zi light zsh-users/zsh-autosuggestions
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

__tb_log "Loading oh-my-zsh lite"
__tb_omz_lite_load

zle -N __tb_lazy_expand_or_complete
bindkey '^I' __tb_lazy_expand_or_complete
bindkey -M emacs '^I' __tb_lazy_expand_or_complete
bindkey -M viins '^I' __tb_lazy_expand_or_complete
bindkey -M vicmd '^I' __tb_lazy_expand_or_complete

# User configuration

PROMPT="%(?:%{$fg[green]%}➜ :%{$fg[red]%}➜ ) %{$fg[cyan]%}%2c%{$reset_color%} "

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

__tb_log "Checking z-shell/zi installation"
if [[ ! -f $HOME/.zi/bin/zi.zsh ]]; then
  print -P "%F{33}▓▒░ %F{160}Installing (%F{33}z-shell/zi%F{160})…%f"
  command mkdir -p "$HOME/.zi" && command chmod go-rwX "$HOME/.zi"
  command git clone -q --depth=1 --branch "main" https://github.com/z-shell/zi "$HOME/.zi/bin" && \
    print -P "%F{33}▓▒░ %F{34}Installation successful.%f%b" || \
    print -P "%F{160}▓▒░ The clone has failed.%f%b"
fi
__tb_log "Loading z-shell/zi"
source "$HOME/.zi/bin/zi.zsh"
autoload -Uz _zi
(( ${+_comps} )) && _comps[zi]=_zi

__tb_log "Loading zsh-autosuggestions"
__tb_load_zi_autosuggestions

__tb_zcompile_async() {
  local helper_path="$TBDIR/init/tb_zcompile_cache"
  local shell_path

  [[ -f "$helper_path" ]] || return 0

  shell_path="$(command -v zsh)"
  [[ -n "$shell_path" ]] || return 0

  if [[ -n "$ZSH_VERSION" ]]; then
    nohup "$shell_path" "$helper_path" \
      "$HOME/.zshrc" \
      "$TBDIR/init/.tbirc" \
      "$TBDIR/init/.zshrc" \
      "$TBDIR/tbr" \
      "$TBDIR/.tbr.cache" \
      >/dev/null 2>&1 &!
  else
    nohup "$shell_path" "$helper_path" \
      "$HOME/.zshrc" \
      "$TBDIR/init/.tbirc" \
      "$TBDIR/init/.zshrc" \
      "$TBDIR/tbr" \
      "$TBDIR/.tbr.cache" \
      >/dev/null 2>&1 &
    disown $! 2>/dev/null || true
  fi
}

__tb_log "Scheduling zinit plugins"
zmodload zsh/sched >/dev/null 2>&1 || true
if whence -w sched >/dev/null 2>&1; then
  sched +1 __tb_load_zi_deferred_plugins >/dev/null 2>&1 || __tb_load_zi_deferred_plugins
else
  __tb_load_zi_deferred_plugins
fi

__tb_zcompile_async

[[ -f "$HOME/.fig/shell/zshrc.post.zsh" ]] && builtin source "$HOME/.fig/shell/zshrc.post.zsh"

# __tb_clear