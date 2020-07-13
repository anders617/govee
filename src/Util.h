#ifndef UTIL_H
#define UTIL_H

#include <cstdarg>
#include <functional>
#include <cstring>

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
