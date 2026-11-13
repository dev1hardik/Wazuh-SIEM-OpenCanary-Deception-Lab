#!/bin/bash
if [ "$1" == "start" ]; then
    echo "Starting Wazuh Manager and Dashboard..."
    sudo systemctl start wazuh-manager wazuh-dashboard
elif [ "$1" == "stop" ]; then
    echo "Stopping Wazuh Manager and Dashboard..."
    sudo systemctl stop wazuh-manager wazuh-dashboard
else
    echo "Usage: ./wazuh_service_control.sh [start|stop]"
fi
