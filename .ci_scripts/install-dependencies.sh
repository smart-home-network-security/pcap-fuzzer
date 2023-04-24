#!/bin/bash

apt update
apt install -y python3-pip
pip3 install -r $GITHUB_WORKSPACE/requirements.txt
