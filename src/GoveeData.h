#ifndef GOVEE_DATA_H
#define GOVEE_DATA_H

#include <string>

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

#endif
