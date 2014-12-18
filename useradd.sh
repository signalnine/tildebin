#!/bin/bash
if [[ $# -eq 0 ]] ; then
    echo 'Usage: useradd.sh [hostlist.txt] [username] [sshpubkey]'
        exit 0
    fi

for i in `cat $1` 
    do echo $i
    ssh -oStrictHostKeyChecking=no $i "sudo useradd -s /bin/bash $2 ; sudo usermod -a -G sysadmin $2 ; sudo mkdir -p /home/$2/.ssh ; echo '$2 ALL=NOPASSWD: ALL' | sudo tee -a /etc/sudoers ; echo '$3' | sudo tee /home/$2/.ssh/authorized_keys ; sudo chown $2 /home/$2 -R" 
done
