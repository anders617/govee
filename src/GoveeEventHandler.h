#ifndef GOVEE_EVENT_HANDLER_H
#define GOVEE_EVENT_HANDLER_H

#include <functional>
#include <optional>
#include <unordered_map>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

namespace govee {

/**
 * Class for parsing bluetooth evt_le_meta_event messages that contain Govee
 * data.
 *
 * Name handlers are called when a message advertising the name for a device is
 * parsed.
 *
 * Data handlers are called when a message containing temp/humidity/battery for
 * a device is parsed.
 */
class GoveeEventParser {
public:
  // Associate `name` with the bluetooth `addr`
  using NameEventHandler =
      std::function<void(std::string_view addr, std::string_view name)>;
  // New data from the given `addr`
  using DataEventHandler = std::function<void(std::string_view addr, float temp,
                                              float humidity, int battery)>;

  GoveeEventParser() : next_handler_id(1) {}

  // Returns the id of the handler which can be used when calling
  // remove_name_handler
  int add_name_handler(NameEventHandler name_handler);
  // Returns the id of the handler which can be used when calling
  // remove_name_handler
  int add_data_handler(DataEventHandler data_handler);

  void remove_name_handler(int id);
  void remove_data_handler(int id);

  void parse(evt_le_meta_event *meta);

private:
  std::optional<std::tuple<float, float, int>> read_data(const uint8_t *data,
                                                         const size_t data_len);

  int next_handler_id;
  std::unordered_map<int, NameEventHandler> name_handlers;
  std::unordered_map<int, DataEventHandler> data_handlers;
};

} // namespace govee

#endif
