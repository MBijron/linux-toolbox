#!/bin/bash

c() {
    local open_in_code="0"
    local filtered_args=()
    local arg

    for arg in "$@"; do
        if [[ "$arg" == "-c" ]]; then
            open_in_code="1"
            continue
        fi
        filtered_args+=("$arg")
    done

    if [[ "${#filtered_args[@]}" -eq 0 ]]; then
        c_print_repo_map
        return 0
    fi

    c_find_and_cd "$open_in_code" "${filtered_args[@]}"
}