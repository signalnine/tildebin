#!/bin/bash
q=$1
if [[ $# -eq 0 ]] ; then
    echo 'Usage: grephosts.sh [search query]'
    exit 0
fi

listec2hosts.py | grep $q | awk '{print $1}'
