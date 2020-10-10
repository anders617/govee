# Building
[Install AWS](https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/setup.html) (For raspberry pi you need to build from source)

Install bluez:
```shell
sudo apt-get install libbluetooth-dev
```

Run `make` from the govee directory and the executable should end up at `build/apps/govee`

# Installing as a system service

Copy `govee.service` to `/etc/systemd/system/govee.service`:
```shell
sudo cp govee.service /etc/systemd/system/govee.service
```

Restart the systemd daemon to load the service file:
```shell
sudo systemctl daemon-reload
```

Copy the `govee` executable to `/bin/govee`:
```shell
sudo cp build/apps/govee /bin/govee
```

Enable the service to automatically start at boot:
```shell
sudo systemctl enable govee.service
```

Or just start/stop the service manually:
```shell
sudo systemctl start govee.service
sudo systemctl stop govee.service
```

Then to view logs:
```shell
sudo journalctl -u govee.service
```
