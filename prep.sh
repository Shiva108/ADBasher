#!/bin/bash
# Internal use only
echo "Folder & filer prepper"
sudo chmod -R +x ./*.sh
sudo chown -R $USER:$(id -gn) -- *
