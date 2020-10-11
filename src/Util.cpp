#include "Util.h"

#include <getopt.h>
#include <iostream>

namespace govee::util {

void Log(const char *format, ...) {
  printf("[%lld] ",
         std::chrono::system_clock::now().time_since_epoch().count());
  va_list arglist;
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  printf("\n");
  fflush(stdout);
}

void print_help() {
  Log("Usage: govee");
  Log("\t--stream_name\tname\t[required]\tName of the AWS Kinesis stream to "
      "push to");
  Log("\t--update_period\t60\t[default=60]\tNumber of seconds between pushes "
      "to the Kinesis stream.");
  Log("\t--scan_duration\t10\t[default=10]\tNumber of seconds to wait for data "
      "from devices before uploading");
}

Args parse_args(int argc, char *argv[]) {
  const struct option longopts[] = {
      {"help", no_argument, 0, 'h'},
      {"stream_name", required_argument, 0, 's'},
      {"update_period", required_argument, 0, 'u'},
      {"scan_duration", required_argument, 0, 'd'},
      {0, 0, 0, 0},
  };
  Args args;
  int index;
  int iarg = 0;
  while (iarg != -1) {
    switch (iarg = getopt_long(argc, argv, "hs:", longopts, &index)) {
    case 'h':
      print_help();
      break;
    case 's':
      args.stream_name = std::string(optarg);
      break;
    case 'u':
      try {
        args.update_period = std::stoll(std::string(optarg));
      } catch (const std::invalid_argument &e) {
        Log("Invalid integer: %s", std::string(optarg));
        print_help();
        exit(0);
      }
      break;
    case 'd':
      try {
        args.scan_duration = std::stoll(std::string(optarg));
      } catch (const std::invalid_argument &e) {
        Log("Invalid integer: %s", std::string(optarg));
        print_help();
        exit(0);
      }
      break;
    }
  }
  return args;
}

} // namespace govee::util