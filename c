#!/bin/bash

c() {
    local open_in_code="0"
    local open_in_vs="0"
    local update_cache="0"
    local filtered_args=()
    local arg

    for arg in "$@"; do
        if [[ "$arg" == "-c" ]]; then
            open_in_code="1"
            continue
        fi
        if [[ "$arg" == "-v" ]]; then
            open_in_vs="1"
            continue
        fi
        if [[ "$arg" == "--update-cache" ]]; then
            update_cache="1"
            continue
        fi
        filtered_args+=("$arg")
    done

    if [[ "$update_cache" == "1" ]]; then
        if [[ "$open_in_code" == "1" || "$open_in_vs" == "1" || "${#filtered_args[@]}" -ne 0 ]]; then
            return 1
        fi

        c_update_repo_map_cache
        return $?
    fi

    if [[ "$open_in_code" == "1" && "$open_in_vs" == "1" ]]; then
        echo "Usage: c [-c|-v] <query> [preferred-index]"
        echo "Error: -c and -v cannot be used together."
        return 1
    fi

    if [[ "${#filtered_args[@]}" -eq 0 ]]; then
        c_print_repo_map
        return 0
    fi

    c_find_and_cd "$open_in_code" "$open_in_vs" "${filtered_args[@]}"
}