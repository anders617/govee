# govee

This application uses bluetooth to scan for [Govee H5075](https://www.amazon.com/Govee-Temperature-Humidity-Notification-Monitor/dp/B07Y36FWTT) devices and pushes the data to an AWS Kinesis stream. Works well on a raspberry pi.

The format of the uploaded data is:
```javascript
{
  "timestamp": 1594685154057511200, // time since unix epoch in nanoseconds
  "temp": 77.8111,                  // temperature in Fahrenheit
  "humidity": 50.6,                 // relative humidity %
  "battery": 100,                   // battery %
  "name": "GVH5075_XXXX"            // the id associated with the device the measurement is from
}
```

# Building
[Install AWS](https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/setup.html) (For raspberry pi you need to build from source)

Install bluez:
```bash
sudo apt-get install libbluetooth-dev
```

Run `make` from the govee directory and the executable should end up at `build/apps/govee`

# Installing as a system service
(These instructions are also in `install.sh`)

Change the ExecStart line in `govee.service` to match your AWS kinesis stream name:
```
ExecStart=/bin/govee --streamname=YOUR_STREAM_NAME
```

Copy `govee.service` to `/etc/systemd/system/govee.service`:
```bash
sudo cp govee.service /etc/systemd/system/govee.service
```

Restart the systemd daemon to load the service file:
```bash
sudo systemctl daemon-reload
```

Copy the `govee` executable to `/bin/govee`:
```bash
sudo cp build/apps/govee /bin/govee
```

Enable the service to automatically start at boot:
```bash
sudo systemctl enable govee.service
```

Or just start/stop the service manually:
```bash
sudo systemctl start govee.service
sudo systemctl stop govee.service
```

Then to view logs:
```bash
sudo journalctl -u govee.service
```
