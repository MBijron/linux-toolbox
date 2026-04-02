#!/bin/bash

go() {
    local repo_path
    local repo_root
    local origin_url
    local browser_url

    if (( $# > 2 )); then
        printf '%s\n' 'Usage: go [query] [preferred-index]' >&2
        return 1
    fi

    if (( $# == 0 )); then
        repo_path="$PWD"
    else
        repo_path="$(go_resolve_repository_path "$1" "$2")" || return $?
    fi

    repo_root="$(go_get_repository_root "$repo_path")" || return $?
    origin_url="$(go_get_origin_remote_url "$repo_root")" || return $?
    browser_url="$(go_convert_remote_url_to_browser_url "$origin_url")" || return $?

    browse "$browser_url" || return $?

    return 0
}

_create_command_wrapper_for_function "go"