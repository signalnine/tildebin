#!/bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'Usage: acrosshosts.sh [hostlist.txt] [command]'
        exit 0
    fi

for i in `cat $1` 
    do echo $i
    ssh -oStrictHostKeyChecking=no $i "$2"
done
