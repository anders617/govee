#include <atomic>
#include <chrono>
#include <csignal>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

#include <aws/core/Aws.h>
#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordRequest.h>
#include <aws/kinesis/model/PutRecordResult.h>

#include "BTScanner.h"
#include "GoveeData.h"
#include "GoveeEventHandler.h"
#include "Util.h"

namespace {

using govee::util::Log;
using govee::GoveeData;
using govee::BTScanner;

// How often data is retrieved from the sensors
const std::chrono::seconds::rep UPDATE_PERIOD_DEFAULT = 60;

// How long to scan for devices during each update
const std::chrono::seconds::rep SCAN_DURATION_DEFAULT = 10;

// bt addr -> device name
std::unordered_map<std::string, std::string> address_to_name;
// bt addr -> latest data
std::unordered_map<std::string, GoveeData> govee_data;

// Bluetooth scanner
BTScanner scanner;
std::atomic<bool> running = true;

// Uploads data in json format to AWS Kinesis
void put_temperatures(
    std::shared_ptr<Aws::Kinesis::KinesisClient> kinesis_client,
    std::string stream_name,
    std::unordered_map<std::string, GoveeData> govee_data) {
  for (const auto &[addr, data] : govee_data) {
    std::string json = to_json(data);
    auto result = kinesis_client->PutRecord(
        Aws::Kinesis::Model::PutRecordRequest()
            .WithStreamName(Aws::String(stream_name))
            .WithData(Aws::Utils::ByteBuffer(
                reinterpret_cast<unsigned char *>(json.data()), json.length()))
            .WithPartitionKey("testing"));
    if (!result.IsSuccess()) {
      Log("[%s] Put Failed", addr.c_str());
      Log("%d", result.GetError().GetErrorType());
      Log(result.GetError().GetMessage().c_str());
    } else {
      Log("[%s] Put success for %s", addr.c_str(), data.name.c_str());
    }
  }
}

// Used to make sure we only store names of govee devices
bool is_govee_name(std::string_view name) {
  return name.compare(0, 7, "GVH5075") == 0 ||
         name.compare(0, 11, "Govee_H5074") == 0;
}

// Event Handlers (called each time a govee name/data message arrives)

void store_name(std::string_view addr, std::string_view name) {
  std::string key(addr);
  if (is_govee_name(name)) {
    address_to_name[key] = name;
  }
}

void log_name(std::string_view addr, std::string_view name) {
  Log("[%s] Name=%s", addr.data(), name.data());
}

void store_data(std::string_view addr, float temp, float humidity,
                int battery) {
  std::string key(addr);
  if (address_to_name.count(key)) {
    govee_data[key] = {
        std::chrono::system_clock::now().time_since_epoch().count(),
        address_to_name[key], temp, humidity, battery};
  }
}

void log_data(std::string_view addr, float temp, float humidity, int battery) {
  Log("[%s] Data={temp: %f, humidity: %f, battery: %d}", addr.data(), temp,
      humidity, battery);
}

// This ensures we shutdown properly by disabling bluetooth scan etc. before
// exiting
void signal_handler(int signal) {
  (void)signal;
  scanner.stop_scanning();
  running = false;
}

} // namespace

int main(int argc, char *argv[]) {
  std::signal(SIGINT, signal_handler);

  govee::util::Args args = govee::util::parse_args(argc, argv);

  if (!args.stream_name) {
    govee::util::print_help();
    return 0;
  }

  std::chrono::seconds::rep update_period =
      args.update_period.value_or(UPDATE_PERIOD_DEFAULT);
  std::chrono::seconds::rep scan_duration =
      args.scan_duration.value_or(SCAN_DURATION_DEFAULT);

  if (scan_duration >= update_period) {
    Log("Scan duration must be less than update period.");
    govee::util::print_help();
    return 0;
  }

  // Setup AWS
  Aws::SDKOptions options;
  options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Info;
  Aws::InitAPI(options);
  govee::util::Defer shutdownAws([=] { Aws::ShutdownAPI(options); });
  auto kinesis_client =
      Aws::MakeShared<Aws::Kinesis::KinesisClient>("KinesisClient");
  std::vector<std::future<void>> aws_threads;

  // Govee event parser
  govee::GoveeEventParser govee_event_parser;

  // Add event handlers to log/store info
  govee_event_parser.add_name_handler(store_name);
  govee_event_parser.add_name_handler(log_name);
  govee_event_parser.add_data_handler(store_data);
  govee_event_parser.add_data_handler(log_data);

  while (running) {
    // Scan for temperatures
    scanner.scan(govee_event_parser, scan_duration);

    // Upload temperatures
    aws_threads.push_back(std::async(std::launch::async, put_temperatures,
                                     kinesis_client, *args.stream_name,
                                     govee_data));

    // Wait until next update
    for (int i = 0; i < update_period - scan_duration; i++) {
      if (!running)
        break;
      sleep(1);
    }

    // Remove finished uploads
    for (int i = aws_threads.size() - 1; i >= 0; i--) {
      if (aws_threads[i].wait_for(std::chrono::seconds(0)) ==
          std::future_status::ready) {
        aws_threads.erase(aws_threads.begin() + i);
      }
    }
  }

  // Wait for uploads to finish before exiting after kill signal
  for (auto &t : aws_threads) {
    t.wait();
  }
  return 0;
}