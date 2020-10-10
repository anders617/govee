#ifndef UTIL_H
#define UTIL_H

#include <cstdarg>
#include <functional>
#include <cstring>

constexpr uint8_t EIR_FLAGS = 0X01;
constexpr uint8_t EIR_NAME_SHORT = 0x08;
constexpr uint8_t EIR_NAME_COMPLETE = 0x09;
constexpr uint8_t EIR_MANUFACTURE_SPECIFIC = 0xFF;

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

#endif
