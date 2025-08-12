#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>
#include "dns_monitor.h"

namespace py = pybind11;

PYBIND11_MODULE(dns_monitor_cpp, m) {
    m.doc() = "High-performance C++ DNS monitoring module";
    
    // Bind DNSQuery struct
    py::class_<DNSQuery>(m, "DNSQuery")
        .def_readwrite("client_id", &DNSQuery::client_id)  // Using correct field name from header
        .def_readwrite("query_name", &DNSQuery::query_name)
        .def_readwrite("query_type", &DNSQuery::query_type)
        .def_readwrite("client_ip", &DNSQuery::client_ip)
        .def_readwrite("server_ip", &DNSQuery::server_ip)
        .def_readwrite("transaction_id", &DNSQuery::transaction_id)
        .def_readwrite("timestamp", &DNSQuery::timestamp)
        .def_readwrite("is_response", &DNSQuery::is_response)
        .def_readwrite("response_code", &DNSQuery::response_code)
        .def_readwrite("response_ips", &DNSQuery::response_ips);
    
    // Bind DeviceConfig struct
    py::class_<DeviceConfig>(m, "DeviceConfig")
        .def(py::init<>())
        .def_readwrite("device_id", &DeviceConfig::device_id)
        .def_readwrite("api_url", &DeviceConfig::api_url)
        .def_readwrite("api_token", &DeviceConfig::api_token)
        .def_readwrite("monitor_interface", &DeviceConfig::monitor_interface)
        .def_readwrite("log_level", &DeviceConfig::log_level)
        .def_readwrite("threat_threshold", &DeviceConfig::threat_threshold)
        .def_readwrite("upload_batch_size", &DeviceConfig::upload_batch_size)
        .def_readwrite("upload_interval_seconds", &DeviceConfig::upload_interval_seconds);
    
    // Bind Statistics struct
    py::class_<DNSMonitor::Statistics>(m, "Statistics")
        .def_readwrite("total_packets", &DNSMonitor::Statistics::total_packets)
        .def_readwrite("dns_packets", &DNSMonitor::Statistics::dns_packets)
        .def_readwrite("uploaded_queries", &DNSMonitor::Statistics::uploaded_queries)
        .def_readwrite("packets_per_second", &DNSMonitor::Statistics::packets_per_second);
    
    // Bind DNSMonitor class
    py::class_<DNSMonitor>(m, "DNSMonitor")
        .def(py::init<const DeviceConfig&>())
        .def("initialize", &DNSMonitor::initialize)
        .def("start", &DNSMonitor::start)
        .def("stop", &DNSMonitor::stop)
        .def("is_running", &DNSMonitor::is_running)
        .def("get_statistics", &DNSMonitor::get_statistics)
        .def("update_config", &DNSMonitor::update_config);
}
