#!/bin/bash
# usage: sniffer_setup.sh <HotspotIP> [<HotspotPW>]
# depends on ssh-keygen and ssh-keyscan and sshpass
HotspotIP=$1
if [ -z "$HotspotIP" ]
then
    echo "sniffer_setup requires a hotspot IP as first argument"
    exit 1
fi

HotspotPW=$2
if [ -z "$HotspotPW" ]
then
    echo "Using default hotspot password"
    HotspotPW=hotspot
fi

echo "Running sniffer_setup on $HotspotIP"

echo "Attempting to Connect"
# the hotspot generates new ssh host keys on every reset
# purge the public key from known hosts (if it's there)
ssh-keygen -f "~.ssh/known_hosts" -R "$HotspotIP"

if [ ! -f "~/.ssh/known_hosts" ]; then
    echo "~/.ssh/known_hosts does not exist. Creating file"
    touch ~/.ssh/known_hosts
fi
# place whatever the new public key is in known hosts
ssh-keyscan $HotspotIP  >> ~/.ssh/known_hosts

# ssh in and reconfigure a few things
sshpass -p $HotspotPW ssh helium@$HotspotIP \
    "(sudo sv d /etc/sv/lora_pkt_fwd_sx1301; \
    sudo sv d /etc/sv/miner; \
    sudo sed -i 's/\"freq\": 912300000/\"freq\": 905900000/' /etc/lorawan/sx1301/global_conf.json;\
    sudo sed -i 's/\"freq\": 913000000/\"freq\": 906600000/' /etc/lorawan/sx1301/global_conf.json;\
    sudo sed -i '/{use_ebus, true},/ a \ \ \ {radio_mirror_port, 1681},' /opt/miner/releases/0.1.0/sys.config;\
    sudo sv u /etc/sv/lora_pkt_fwd_sx1301; \
    sudo sv u /etc/sv/miner; \
    exit)"