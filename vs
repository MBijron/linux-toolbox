#!/bin/bash

vs() {
    local target="${1:-.}"
    local executable_path
    local wsl_target
    local launch_wsl_target
    local first_solution_file
    local src_dir
    local windows_target

    executable_path="$(vs_get_visual_studio_executable_path)" || return $?
    vs_validate_executable_exists "$executable_path" || return $?

    wsl_target="$(code_convert_target_to_wsl_path "$target")" || return $?

    if [ ! -e "$wsl_target" ]; then
        printf '%s\n' 'Using c to resolve path'
        c "$@" -v
        return $?
    fi

    launch_wsl_target="$wsl_target"

    if [ -d "$wsl_target" ]; then
        src_dir="$wsl_target/src"

        if [ -d "$src_dir" ]; then
            first_solution_file="$(find "$src_dir" -maxdepth 1 -mindepth 1 -type f -name '*.sln' 2>/dev/null | head -n 1)"
        fi

        if [ -z "$first_solution_file" ]; then
            first_solution_file="$(find "$wsl_target" -mindepth 1 -maxdepth 2 -type f -name '*.sln' 2>/dev/null | head -n 1)"
        fi

        if [ -n "$first_solution_file" ]; then
            launch_wsl_target="$first_solution_file"
        fi
    fi

    windows_target="$(code_convert_wsl_path_to_windows_path "$launch_wsl_target")" || return $?

    printf '%s\n' "$windows_target"
    vs_launch_with_windows_path "$executable_path" "$windows_target" || return $?

    return 0
}