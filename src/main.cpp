#include <atomic>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <chrono>
#include <csignal>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <thread>
#include <set>
#include <string>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdarg>
#include <aws/core/Aws.h>
#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordRequest.h>
#include <aws/kinesis/model/PutRecordResult.h>

#define EIR_FLAGS 0X01
#define EIR_NAME_SHORT 0x08
#define EIR_NAME_COMPLETE 0x09
#define EIR_MANUFACTURE_SPECIFIC 0xFF

struct Defer {
  Defer(std::function<void(void)> pFunc) : func(pFunc){};
  std::function<void(void)> func;
  virtual ~Defer() {
    func();
  }
};

#define CHECK(expr, msg)                                                       \
  if (!CHECK_IMPL(expr, msg))                                                  \
    return 0;
#define RETURN_OR_DIE(expr, msg)                                               \
  expr;                                                                        \
  CHECK(expr, msg);

template <typename T> bool CHECK_IMPL(T t, const std::string &msg) {
  if (t < 0) {
    std::cerr << "CHECK FAILED" << std::endl;
    std::cerr << msg << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return false;
  }
  return true;
}

struct GoveeData {
  long long int timestamp;
  float temp, humidity;
  int battery;
};

std::string to_json(const GoveeData &data) {
  std::stringstream s;
  s << "{\"timestamp\":" << data.timestamp << 
        ",\"temp\":" << data.temp << 
        ",\"humidity\":" << data.humidity <<
         ",\"battery\":" << data.battery << 
      "}";
  return s.str();
}

const int ON = 1;
const int OFF = 0;
const std::chrono::seconds::rep SCAN_DURATION = 10;

std::set<bdaddr_t> addresses;
std::map<bdaddr_t, std::pair<std::string, GoveeData>> govee_data;
std::atomic<bool> running = true;
std::vector<std::thread> awsThreads;

bool operator==(const bdaddr_t &a, const bdaddr_t &b) {
  return ((a.b[0] == b.b[0]) && (a.b[1] == b.b[1]) && (a.b[2] == b.b[2]) &&
          (a.b[3] == b.b[3]) && (a.b[4] == b.b[4]) && (a.b[5] == b.b[5]));
}
bool operator<(const bdaddr_t &a, const bdaddr_t &b) {
  unsigned long long A = a.b[5];
  A = A << 8 | a.b[4];
  A = A << 8 | a.b[3];
  A = A << 8 | a.b[2];
  A = A << 8 | a.b[1];
  A = A << 8 | a.b[0];
  unsigned long long B = b.b[5];
  B = B << 8 | b.b[4];
  B = B << 8 | b.b[3];
  B = B << 8 | b.b[2];
  B = B << 8 | b.b[1];
  B = B << 8 | b.b[0];
  return (A < B);
}

void Log(const char *format, ...) {
  printf("[%lld] ", std::chrono::steady_clock::now().time_since_epoch().count());
  va_list arglist;
  va_start( arglist, format );
  vprintf( format, arglist );
  va_end( arglist );
  printf("\n");
}

void put_temperatures(std::shared_ptr<Aws::Kinesis::KinesisClient> kinesis_client) {
  for (auto pair : govee_data) {
    std::string json = to_json(pair.second.second);
    auto result = kinesis_client->PutRecord(Aws::Kinesis::Model::PutRecordRequest()
                              .WithStreamName(Aws::String("govee-data-" + pair.second.first))
                              .WithData(Aws::Utils::ByteBuffer(reinterpret_cast<unsigned char*>(json.data()), json.length()))
                              .WithPartitionKey("testing"));
    if (!result.IsSuccess()) {
      Log("Put Failed");
      Log("%d", result.GetError().GetErrorType());
      Log(result.GetError().GetMessage().c_str());
    } else {
      Log("Put success for %s", pair.second.first.c_str());
    }
  }
}

bool is_govee_name(const std::string &name) {
  return name.compare(0, 7, "GVH5075") == 0 ||
         name.compare(0, 11, "Govee_H5074") == 0;
}

std::optional<GoveeData> read_msg(const uint8_t *data, const size_t data_len,
              const le_advertising_info *info) {
  (void)info;
  if ((data[1] == 0x88) && (data[2] == 0xEC)) {
    float temp = -1, humidity = -1;
    int battery = -1;
    if (data_len == 9) {
      // This data came from https://github.com/Thrilleratplay/GoveeWatcher
      // 88ec00 03519e 6400 Temp: 21.7502°C Temp: 71.1504°F Humidity: 50.2%
      // 1 2 3  4 5 6  7 8
      int iTemp = int(data[4]) << 16 | int(data[5]) << 8 | int(data[6]);
      temp = ((float(iTemp) / 10000.0) * 9.0 / 5.0) + 32.0;
      humidity = float(iTemp % 1000) / 10.0;
      battery = int(data[7]);
    } else if (data_len == 10) {
      // This data came from
      // https://github.com/neilsheps/GoveeTemperatureAndHumidity 88ec00 dd07
      // 9113 64 02 1 2 3  4 5  6 7  8  9
      int iTemp = int(data[5]) << 8 | int(data[4]);
      int iHumidity = int(data[7]) << 8 | int(data[6]);
      temp = ((float(iTemp) / 100.0) * 9.0 / 5.0) + 32.0;
      humidity = float(iHumidity) / 100.0;
      battery = int(data[8]);
    }
    Log("temp: %f humidity: %f battery: %d", temp, humidity, battery);
    GoveeData data = {std::chrono::system_clock::now().time_since_epoch().count(), temp, humidity, battery};
    return data;
  }
  return std::nullopt;
}

void process_event(evt_le_meta_event *meta) {
  if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
    return;
  le_advertising_info *info = (le_advertising_info *)(meta->data + 1);
  if (!info->length)
    return;
  int current_offset = 0;
  bool data_error = false;
  while (!data_error && current_offset < info->length) {
    size_t data_len = info->data[current_offset];
    if (data_len + 1 > info->length) {
      Log("EIR data length is longer than EIR packet length. %d + 1 %d", data_len, info->length);
      data_error = true;
    } else {
      // Bluetooth Extended Inquiry Response
      // I'm paying attention to only three types of EIR, Short Name,
      // Complete Name, and Manufacturer Specific Data The names are how I
      // learn which Bluetooth Addresses I'm going to listen to
      bool is_govee_device = (addresses.end() != addresses.find(info->bdaddr));
      char addr[19] = {0};
      ba2str(&info->bdaddr, addr);
      if ((info->data + current_offset + 1)[0] == EIR_NAME_SHORT ||
          (info->data + current_offset + 1)[0] == EIR_NAME_COMPLETE) {
        std::string name((char *)&((info->data + current_offset + 1)[1]),
                         data_len - 1);
        if (is_govee_name(name)) {
          addresses.insert(info->bdaddr);
          if (!govee_data.count(info->bdaddr)) {
            govee_data[info->bdaddr] = {name, {}};
          }
        }
        Log("[%s] Name: %s", addr, name.c_str());
      } else if (is_govee_device) {
        if ((info->data + current_offset + 1)[0] == EIR_MANUFACTURE_SPECIFIC) {
          if(auto new_data = read_msg((info->data + current_offset + 1), data_len, info)) {
            govee_data[info->bdaddr].second = *new_data;
          }
        }
      }
      current_offset += data_len + 1;
    }
  }
}

std::pair<int, std::unique_ptr<unsigned char[]>>
read_device(int device_handle) {
  auto buf = std::make_unique<unsigned char[]>(HCI_MAX_EVENT_SIZE);
  // The following while loop attempts to read from the non-blocking socket.
  // As long as the read call simply times out, we sleep for 100
  // microseconds and try again.
  int len = 0;
  while ((len = read(device_handle, buf.get(),
                     sizeof(unsigned char) * HCI_MAX_EVENT_SIZE)) < 0) {
    if (errno == EINTR) {
      // EINTR : Interrupted function call (POSIX.1-2001); see signal(7).
      running = false;
    }
    if (running && errno == EAGAIN) {
      // EAGAIN : Resource temporarily unavailable (may be the same value as
      // EWOULDBLOCK) (POSIX.1-2001).
      usleep(1000);
    }
    return {-1, std::move(buf)};
  }
  return {len, std::move(buf)};
}

int scan(int device_handle, std::shared_ptr<Aws::Kinesis::KinesisClient> kinesis_client) {
  bool error = false;
  while (running) {
    auto scanStartTime = std::chrono::steady_clock::now();
    while (running && !error) {
      if (std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::steady_clock::now() - scanStartTime)
              .count() > SCAN_DURATION) {
        Log("Scan Complete");
        break;
      }
      auto [len, buf] = read_device(device_handle);
      if (running && len != -1) {
        evt_le_meta_event *meta =
            (evt_le_meta_event *)(buf.get() + (1 + HCI_EVENT_HDR_SIZE));
        len -= (1 + HCI_EVENT_HDR_SIZE);
        process_event(meta);
      }
    }
    CHECK(hci_le_set_scan_enable(device_handle, 0x00, 1, 1000),
          "hci_le_set_scan_enable"); // Distable bt scan while sleeping
    awsThreads.emplace_back(put_temperatures, kinesis_client);
    for (int i = 0; i < 60 - SCAN_DURATION; i++) {
      sleep(1);
      if (!running)
        return 0;
    }
    CHECK(hci_le_set_scan_enable(device_handle, 0x01, 1, 1000),
          "hci_le_set_scan_enable disable"); // Enable bt scan after
  }
  return 0;
}

void signal_handler(int signal) {
  (void)signal;
  running = false;
}

int main() {
  std::signal(SIGINT, signal_handler);
  int device_id = RETURN_OR_DIE(hci_get_route(NULL), "hci_get_route");
  int device_handle = RETURN_OR_DIE(hci_open_dev(device_id), "hci_open_dev");
  Defer closeDevice([=] { hci_close_dev(device_handle); });
  CHECK(ioctl(device_handle, FIONBIO, (char *)&ON), "set device on");
  hci_le_set_scan_enable(
      device_handle, 0x00, 1,
      1000); // No check since we just want to ensure it is disabled (will
             // return -1 if it was already disabled)
  CHECK(hci_le_set_scan_parameters(device_handle, 0x01, htobs(0x0010),
                                   htobs(0x0010), 0x00, 0x00, 1000),
        "hci_le_set_scan_parameters");

  CHECK(hci_le_set_scan_enable(device_handle, 0x01, 1, 1000),
        "hci_le_set_scan_enable");
  Defer disableScan(
      [=] { hci_le_set_scan_enable(device_handle, 0x00, 1, 1000); });
  struct hci_filter original_filter;
  socklen_t olen = sizeof(original_filter);
  CHECK(getsockopt(device_handle, SOL_HCI, HCI_FILTER, &original_filter, &olen),
        "getsockopt");
  struct hci_filter new_filter;
  hci_filter_clear(&new_filter);
  hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
  hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);
  CHECK(setsockopt(device_handle, SOL_HCI, HCI_FILTER, &new_filter,
                   sizeof(new_filter)),
        "setsockopt");
  Defer setOriginalSockOpt([=] {
    setsockopt(device_handle, SOL_HCI, HCI_FILTER, &original_filter,
               sizeof(original_filter));
  });

  Aws::SDKOptions options;
  options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Info;
  Aws::InitAPI(options);
  Defer shutdownAws([=]{Aws::ShutdownAPI(options);});
  auto kinesis_client = Aws::MakeShared<Aws::Kinesis::KinesisClient>("test");
  CHECK(scan(device_handle, kinesis_client), "scanning");
  for (auto &t : awsThreads) {
    t.join();
  }
  return 0;
}