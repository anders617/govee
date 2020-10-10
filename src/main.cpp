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
#include <unordered_map>
#include <getopt.h>

#include <aws/core/Aws.h>
#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordRequest.h>
#include <aws/kinesis/model/PutRecordResult.h>

#include "BTScanner.h"
#include "Util.h"
#include "GoveeEventHandler.h"
#include "GoveeData.h"

struct Args {
  std::optional<std::string> stream_name;
};

void print_help() {
  Log("Usage: govee --streamname govee-data");
}

Args parse_args(int argc, char *argv[]) {
  const struct option longopts[] = {
    {"help",      no_argument,        0, 'h'},
    {"streamname",     required_argument,  0, 's'},
    {0,0,0,0},
  };
  Args args;
  int index;
  int iarg=0;
  while(iarg != -1) {
    switch (iarg = getopt_long(argc, argv, "hs:", longopts, &index)) {
      case 'h':
        print_help();
        break;
      case 's':
        args.stream_name = std::string(optarg);
        break;
    }
  }
  return args;
}

// How often data is retrieved from the sensors
const std::chrono::seconds::rep UPDATE_PERIOD = 60;

// How long to scan for devices during each update
const std::chrono::seconds::rep SCAN_DURATION = 10;

// bt addr -> device name
std::unordered_map<std::string, std::string> address_to_name;
// bt addr -> latest data
std::unordered_map<std::string, GoveeData> govee_data;

// Bluetooth scanner
BTScanner scanner;
std::atomic<bool> running = true;

// Uploads data in json format to AWS Kinesis
void put_temperatures(
    std::shared_ptr<Aws::Kinesis::KinesisClient> kinesis_client, std::string stream_name) {
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

void store_data(std::string_view addr, float temp, float humidity, int battery) {
  std::string key(addr);
  if (address_to_name.count(key)) {
    govee_data[key] = {
      std::chrono::system_clock::now().time_since_epoch().count(), 
      address_to_name[key], 
      temp, 
      humidity, 
      battery
    };
  }
}

void log_data(std::string_view addr, float temp, float humidity, int battery) {
    Log("[%s] Data={temp: %f, humidity: %f, battery: %d}", addr.data(), temp, humidity, battery);
}

// This ensures we shutdown properly by disabling bluetooth scan etc. before
// exiting
void signal_handler(int signal) {
  (void)signal;
  scanner.stop_scanning();
  running = false;
}

int main(int argc, char *argv[]) {
  std::signal(SIGINT, signal_handler);

  Args args = parse_args(argc, argv);

  if (!args.stream_name) {
    print_help();
    return 0;
  }

  // Setup AWS
  Aws::SDKOptions options;
  options.loggingOptions.logLevel = Aws::Utils::Logging::LogLevel::Info;
  Aws::InitAPI(options);
  Defer shutdownAws([=] { Aws::ShutdownAPI(options); });
  auto kinesis_client = Aws::MakeShared<Aws::Kinesis::KinesisClient>("KinesisClient");
  std::vector<std::thread> awsThreads;

  // Govee event parser
  GoveeEventParser govee_event_parser;

  // Add event handlers to log/store info
  govee_event_parser.add_name_handler(store_name);
  govee_event_parser.add_name_handler(log_name);
  govee_event_parser.add_data_handler(store_data);
  govee_event_parser.add_data_handler(log_data);

  while (running) {
    // Scan for temperatures
    scanner.scan(govee_event_parser, SCAN_DURATION);

    // Upload temperatures
    awsThreads.emplace_back(put_temperatures, kinesis_client, *args.stream_name);

    // Wait until next update
    for (int i = 0; i < UPDATE_PERIOD - SCAN_DURATION; i++) {
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