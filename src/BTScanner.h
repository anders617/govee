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

#include "Util.h"

namespace govee {

// Class for scanning for evt_le_meta_event bluetooth events.
//
// Can be used with a function handler:
// BTScanner scanner;
// scanner.scan([](evt_le_meta_event *meta) {
//    std::cout << "Received meta event" << std::endl;
// }, 10);
//
// Or with an object handler containing a parse method:
// class EventParser { void parse(evt_le_meta_event *meta) {...}};
// EventParser parser;
// BTScanner scanner;
// scanner.scan(parser, 10);
class BTScanner {
public:
  // Scan from device with addr "XX:XX:XX:XX:XX:XX"
  BTScanner(const std::string &bd_addr);

  // Scan from default device
  BTScanner();

  ~BTScanner();

  // Scans for scan_duration seconds.
  // handle_message is a function which is called every time a evt_le_meta_event
  // is received. The function can return true to stop scanning.
  bool scan(std::function<bool(evt_le_meta_event *)> handle_message,
            std::chrono::seconds::rep scan_duration);

  // Scans for scan_duration seconds.
  // event_handler is an object with a void parse(evt_le_meta_event *) method
  // that is called each time a evt_le_meta_event is received.
  template <typename T>
  bool scan(T &event_handler, std::chrono::seconds::rep scan_duration);

  // Stop scanning bluetooth short of scan_duration.
  void stop_scanning();

private:
  void setup(int device_id);
  void cleanup();
  std::pair<int, std::unique_ptr<unsigned char[]>> read_device();

  int device_handle;
  std::atomic<bool> scanning;
  struct hci_filter original_filter;
};

template <typename T>
bool BTScanner::scan(T &event_handler,
                     std::chrono::seconds::rep scan_duration) {
  bool error = false;
  scanning = true;
  auto scanStartTime = std::chrono::steady_clock::now();
  // Enable scanning
  util::CHECK(hci_le_set_scan_enable(device_handle, 0x01, 1, 1000),
              "Failed to enable scan");
  while (scanning && !error) {
    if (std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - scanStartTime)
            .count() > scan_duration) {
      break;
    }
    auto [len, buf] = read_device();
    if (scanning && len != -1) {
      evt_le_meta_event *meta =
          (evt_le_meta_event *)(buf.get() + (1 + HCI_EVENT_HDR_SIZE));
      len -= (1 + HCI_EVENT_HDR_SIZE);
      event_handler.parse(meta);
    }
  }
  // Disable scanning
  util::CHECK(hci_le_set_scan_enable(device_handle, 0x00, 1, 1000),
              "Failed to disable scan");
  return false;
}

} // namespace govee

#endif
