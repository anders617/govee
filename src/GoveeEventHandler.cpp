#include "GoveeEventHandler.h"

#include "Util.h"

int GoveeEventParser::add_name_handler(NameEventHandler name_handler) {
  int id = next_handler_id++;
  name_handlers[id] = name_handler;
  return next_handler_id;
}

int GoveeEventParser::add_data_handler(DataEventHandler data_handler) {
  int id = next_handler_id++;
  data_handlers[id] = data_handler;
  return next_handler_id;
}

void GoveeEventParser::remove_name_handler(int id) {
  name_handlers.erase(id);
}

void GoveeEventParser::remove_data_handler(int id) {
  data_handlers.erase(id);
}

std::optional<std::tuple<float, float, int>> GoveeEventParser::read_data(const uint8_t *data, const size_t data_len) {
  if (data_len != 9 && data_len != 10) return std::nullopt;
  if ((data[1] == 0x88) && (data[2] == 0xEC)) {
    float temp = -1, humidity = -1;
    int battery = -1;
    if (data_len == 9) {
      // This data came from https://github.com/Thrilleratplay/GoveeWatcher
      // 88ec00 03519e 6400 Temp: 21.7502°C Temp: 71.1504°F Humidity: 50.2%
      // 1 2 3  4 5 6  7 8
      int temp_humidity = int(data[4]) << 16 | int(data[5]) << 8 | int(data[6]);
      int humidity_component = temp_humidity % 1000;
      int temp_component = temp_humidity - humidity_component;
      temp = ((float(temp_component) / 10000.0) * 9.0 / 5.0) + 32.0;
      humidity = float(humidity_component % 1000) / 10.0;
      battery = int(data[7]);
    } else if (data_len == 10) {
      Log("Data length 10");
      // This data came from
      // https://github.com/neilsheps/GoveeTemperatureAndHumidity 88ec00 dd07
      // 9113 64 02 1 2 3  4 5  6 7  8  9
      int iTemp = int(data[5]) << 8 | int(data[4]);
      int iHumidity = int(data[7]) << 8 | int(data[6]);
      temp = ((float(iTemp) / 100.0) * 9.0 / 5.0) + 32.0;
      humidity = float(iHumidity) / 100.0;
      battery = int(data[8]);
    }
    return std::make_tuple(temp, humidity, battery);
  }
  return std::nullopt;
}

void GoveeEventParser::parse(evt_le_meta_event *meta) {
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
      std::string_view strAddr(addr);
      if ((info->data + current_offset + 1)[0] == EIR_NAME_SHORT ||
          (info->data + current_offset + 1)[0] == EIR_NAME_COMPLETE) {
        std::string name((char *)&((info->data + current_offset + 1)[1]), data_len-1);
        for (const auto &[id, name_handler] : name_handlers) {
          name_handler(strAddr, name);
        }
      } else if ((info->data + current_offset + 1)[0] == EIR_MANUFACTURE_SPECIFIC) {
        if (auto new_data =
                read_data((info->data + current_offset + 1), data_len)) {
          const auto [temp, humidity, battery] = *new_data;
          for (const auto &[id, data_handler] : data_handlers) {
            data_handler(strAddr, temp, humidity, battery);
          }
        }
      }
      current_offset += data_len + 1;
    }
  }
}
