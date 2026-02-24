#!/bin/bash

c() {
    if [[ "$#" -eq 0 ]]; then
        c_print_repo_map
        return 0
    fi

    c_find_and_cd "$@"
}