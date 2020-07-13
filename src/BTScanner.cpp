#include "BTScanner.h"

#include <iostream>

#include "Util.h"

const int ON = 1;
const int OFF = 0;

BTScanner::BTScanner(const std::string &bd_addr) {
  bdaddr_t ba;
  CHECK(str2ba(bd_addr.c_str(), &ba), "Invalid string address: " + bd_addr);
  int device_id = CHECK(hci_get_route(&ba), "Failed to get route");
  setup(device_id);
}

BTScanner::BTScanner() {
  int device_id =
      CHECK(hci_get_route(NULL), "Failed to get route"); // get device
  setup(device_id);
}

BTScanner::~BTScanner() { cleanup(); }

void BTScanner::stop_scanning() { scanning = false; }

void BTScanner::setup(int device_id) {
  // get device handle
  device_handle = CHECK(hci_open_dev(device_id), "Failed to open device");
  // make sure device is on
  ioctl(device_handle, FIONBIO, (char *)&ON);
  // make sure scan is off
  hci_le_set_scan_enable(device_handle, 0x00, 1, 1000);
  // Setup scan parameters
  CHECK(hci_le_set_scan_parameters(device_handle, 0x01, htobs(0x0010),
                                   htobs(0x0010), 0x00, 0x00, 1000),
        "Failed to set parameters");
  // Setup new filter to look for packets we want
  struct hci_filter new_filter;
  hci_filter_clear(&new_filter);
  hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
  hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);
  // Set filter
  CHECK(setsockopt(device_handle, SOL_HCI, HCI_FILTER, &new_filter,
                   sizeof(new_filter)),
        "Failed to set filter");
}

void BTScanner::cleanup() {
  // Make sure scan is disabled
  hci_le_set_scan_enable(device_handle, 0x00, 1, 1000);
  // Close the device
  hci_close_dev(device_handle);
}

std::pair<int, std::unique_ptr<unsigned char[]>> BTScanner::read_device() {
  auto buf = std::make_unique<unsigned char[]>(HCI_MAX_EVENT_SIZE);
  // The following while loop attempts to read from the non-blocking socket.
  // As long as the read call simply times out, we sleep for 100
  // microseconds and try again.
  int len = 0;
  while ((len = read(device_handle, buf.get(),
                     sizeof(unsigned char) * HCI_MAX_EVENT_SIZE)) < 0) {
    if (errno == EINTR) {
      // EINTR : Interrupted function call (POSIX.1-2001); see signal(7).
      scanning = false;
    }
    if (scanning && errno == EAGAIN) {
      // EAGAIN : Resource temporarily unavailable (may be the same value as
      // EWOULDBLOCK) (POSIX.1-2001).
      usleep(100);
    }
    return {-1, std::move(buf)};
  }
  return {len, std::move(buf)};
}

bool BTScanner::scan(std::function<bool(evt_le_meta_event *)> handle_message,
                     std::chrono::seconds::rep scan_duration) {
  bool error = false;
  scanning = true;
  auto scanStartTime = std::chrono::steady_clock::now();
  // Enable scanning
  CHECK(hci_le_set_scan_enable(device_handle, 0x01, 1, 1000),
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
      if (handle_message(meta)) {
        scanning = false;
      }
    }
  }
  // Disable scanning
  CHECK(hci_le_set_scan_enable(device_handle, 0x00, 1, 1000),
        "Failed to disable scan");
  return false;
}
