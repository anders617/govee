#ifndef BT_SCANNER_H
#define BT_SCANNER_H

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

class BTScanner {
public:
  // Scan from device with addr "XX:XX:XX:XX:XX:XX"
  BTScanner(const std::string &bd_addr);

  // Scan from default device
  BTScanner();

  ~BTScanner();

  bool scan(std::function<bool(evt_le_meta_event *)> handle_message,
            std::chrono::seconds::rep scan_duration);
  void stop_scanning();

private:
  void setup(int device_id);
  void cleanup();
  std::pair<int, std::unique_ptr<unsigned char[]>> read_device();

  int device_handle;
  std::atomic<bool> scanning;
  struct hci_filter original_filter;
};

#endif
