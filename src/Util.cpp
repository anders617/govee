#include "Util.h"

#include <chrono>
#include <iostream>

void Log(const char *format, ...) {
  printf("[%lld] ",
         std::chrono::steady_clock::now().time_since_epoch().count());
  va_list arglist;
  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
  printf("\n");
}
