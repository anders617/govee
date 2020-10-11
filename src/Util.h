#ifndef UTIL_H
#define UTIL_H

#include <chrono>
#include <cstdarg>
#include <cstring>
#include <functional>

constexpr uint8_t EIR_FLAGS = 0X01;
constexpr uint8_t EIR_NAME_SHORT = 0x08;
constexpr uint8_t EIR_NAME_COMPLETE = 0x09;
constexpr uint8_t EIR_MANUFACTURE_SPECIFIC = 0xFF;

namespace govee::util {

void Log(const char *format, ...);

struct Defer {
  Defer(std::function<void(void)> pFunc) : func(pFunc){};
  std::function<void(void)> func;
  virtual ~Defer() { func(); }
};

template <typename T> T CHECK(T t, const std::string &msg) {
  if (t < 0) {
    Log("CHECK FAILED");
    Log(msg.c_str());
    Log(std::strerror(errno));
  }
  return t;
}

struct Args {
  std::optional<std::string> stream_name;
  std::optional<std::chrono::seconds::rep> update_period;
  std::optional<std::chrono::seconds::rep> scan_duration;
};

void print_help();

Args parse_args(int argc, char *argv[]);

} // namespace govee::util

#endif
