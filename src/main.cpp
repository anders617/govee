#include <atomic>
#include <chrono>
#include <csignal>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <map>

#include <aws/core/Aws.h>
#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordRequest.h>
#include <aws/kinesis/model/PutRecordResult.h>

#include "BTScanner.h"
#include "Util.h"

#define EIR_FLAGS 0X01
#define EIR_NAME_SHORT 0x08
#define EIR_NAME_COMPLETE 0x09
#define EIR_MANUFACTURE_SPECIFIC 0xFF

struct GoveeData {
  long long int timestamp;
  std::string name;
  float temp, humidity;
  int battery;
};

std::string to_json(const GoveeData &data) {
  std::stringstream s;
  s << "{\"timestamp\":" << data.timestamp << ",\"temp\":" << data.temp
    << ",\"humidity\":" << data.humidity << ",\"battery\":" << data.battery
    << ",\"name\":\"" << data.name << "\""
    << "}";
  return s.str();
}

const std::chrono::seconds::rep SCAN_DURATION = 10;
BTScanner scanner;
std::map<std::string, std::string> addressToName;
std::map<std::string, GoveeData> govee_data;
std::atomic<bool> running = true;
std::vector<std::thread> awsThreads;

void put_temperatures(
    std::shared_ptr<Aws::Kinesis::KinesisClient> kinesis_client) {
  for (auto pair : govee_data) {
    std::string json = to_json(pair.second);
    auto result = kinesis_client->PutRecord(
        Aws::Kinesis::Model::PutRecordRequest()
            .WithStreamName(Aws::String("govee-data"))
            .WithData(Aws::Utils::ByteBuffer(
                reinterpret_cast<unsigned char *>(json.data()), json.length()))
            .WithPartitionKey("testing"));
    if (!result.IsSuccess()) {
      Log("Put Failed");
      Log("%d", result.GetError().GetErrorType());
      Log(result.GetError().GetMessage().c_str());
    } else {
      Log("Put success for %s", addressToName[pair.first].c_str());
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

    char addr[19] = {0};
    ba2str(&info->bdaddr, addr);
    std::string strAddr(addr);
    GoveeData data = {
        std::chrono::system_clock::now().time_since_epoch().count(),
        addressToName[strAddr], temp, humidity, battery};
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
      Log("EIR data length is longer than EIR packet length. %d + 1 %d",
          data_len, info->length);
      data_error = true;
    } else {
      // Bluetooth Extended Inquiry Response
      // I'm paying attention to only three types of EIR, Short Name,
      // Complete Name, and Manufacturer Specific Data The names are how I
      // learn which Bluetooth Addresses I'm going to listen to
      char addr[19] = {0};
      ba2str(&info->bdaddr, addr);
      std::string strAddr(addr);
      bool is_govee_device =
          (addressToName.end() != addressToName.find(strAddr));
      if ((info->data + current_offset + 1)[0] == EIR_NAME_SHORT ||
          (info->data + current_offset + 1)[0] == EIR_NAME_COMPLETE) {
        std::string name((char *)&((info->data + current_offset + 1)[1]),
                         data_len - 1);
        if (is_govee_name(name)) {
          addressToName[strAddr] = name;
        }
        Log("[%s] Name: %s", addr, name.c_str());
      } else if (is_govee_device) {
        if ((info->data + current_offset + 1)[0] == EIR_MANUFACTURE_SPECIFIC) {
          if (auto new_data =
                  read_msg((info->data + current_offset + 1), data_len, info)) {
            govee_data[strAddr] = *new_data;
          }
        }
      }
      current_offset += data_len + 1;
    }
  }
}

// This ensures we shutdown properly by disabling bluetooth scan etc. before
// exiting
void signal_handler(int signal) {
  (void)signal;
  scanner.stop_scanning();
  running = false;
}

int main() {
  std::signal(SIGINT, signal_handler);

  Aws::SDKOptions options;
  options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Info;
  Aws::InitAPI(options);
  Defer shutdownAws([=] { Aws::ShutdownAPI(options); });
  auto kinesis_client = Aws::MakeShared<Aws::Kinesis::KinesisClient>("test");
  while (running) {
    // Scan for temperatures
    scanner.scan(
        [](evt_le_meta_event *event) {
          process_event(event);
          return false;
        },
        SCAN_DURATION);

    // Upload temperatures
    awsThreads.emplace_back(put_temperatures, kinesis_client);
    for (int i = 0; i < 60 - SCAN_DURATION; i++) {
      if (!running)
        break;
      sleep(1);
    }
  }
  // Wait for uploads to finish before exiting
  for (auto &t : awsThreads) {
    t.join();
  }
  return 0;
}