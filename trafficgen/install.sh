# this fixes mininet bug with ovs-controller
apt-get install -y openvswitch-testcontroller mininet ethtool netcat tcpreplay python3-numpy python3-matplotlib python3-scapy tcpdump
cp /usr/bin/ovs-testcontroller /usr/bin/ovs-controller
systemctl stop openvswitch-testcontroller
