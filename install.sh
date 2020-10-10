#!/bin/bash

make

sudo cp govee.service /etc/systemd/system/govee.service

sudo systemctl daemon-reload

sudo cp build/apps/govee /bin/govee

sudo systemctl enable govee.service

sudo systemctl start govee.service
