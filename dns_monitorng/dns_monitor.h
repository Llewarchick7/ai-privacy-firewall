#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>

// Forward declarations
struct pcap;
typedef struct pcap pcap_t;

struct DNSQuery {
    std::string device_id;
    std::string query_name;
    std::string query_type;
    std::string client_ip;
    std::string server_ip;
    uint16_t transaction_id;
    uint64_t timestamp;
    bool is_response;
    std::string response_code;
    std::vector<std::string> response_ips;
};

/*
Configuration for Device 
This structure holds the configuration parameters for the DNS monitoring device.
It includes device-specific identifiers, API endpoints, and monitoring settings.
*/
struct DeviceConfig {
    std::string device_id;
    std::string api_url;
    std::string api_token;
    std::string monitor_interface;
    std::string log_level;
    double threat_threshold = 0.7; // Threshold for threat detection
    int upload_batch_size = 100;    // Number of queries to upload in a single batch
    int upload_interval_seconds = 30; // Interval between uploads
};

class DNSMonitor {
private:
    DeviceConfig config_;
    pcap_t* pcap_handle_;
    std::atomic<bool> running_;
    
    // Thread-safe queue for DNS queries
    std::queue<DNSQuery> query_queue_;
    std::mutex queue_mutex_;
    
    // Background threads
    std::thread capture_thread_;
    std::thread upload_thread_;
    
    // Statistics
    std::atomic<uint64_t> total_packets_;
    std::atomic<uint64_t> dns_packets_;
    std::atomic<uint64_t> uploaded_queries_;

public:
    explicit DNSMonitor(const DeviceConfig& config);
    ~DNSMonitor();
    
    // Main control methods
    bool initialize();
    void start();
    void stop();
    bool is_running() const { return running_.load(); }
    
    // Configuration
    bool load_config(const std::string& config_path);
    void update_config(const DeviceConfig& new_config);
    
    // Statistics
    struct Statistics {
        uint64_t total_packets;
        uint64_t dns_packets;
        uint64_t uploaded_queries;
        double packets_per_second;
    };
    Statistics get_statistics() const;
    
private:
    // Core processing methods
    void packet_capture_loop();
    void upload_loop();
    
    // Packet processing
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet);
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    
    // DNS parsing
    bool parse_dns_packet(const u_char* packet, size_t packet_len, DNSQuery& query);
    std::string parse_dns_name(const u_char* packet, size_t packet_len, size_t& offset);
    std::string get_query_type_string(uint16_t qtype);
    std::string get_response_code_string(uint8_t rcode);
    
    // Network utilities
    std::string ip_to_string(uint32_t ip);
    std::string get_device_id();
    std::string get_local_ip();
    std::string get_mac_address();
    
    // API communication
    bool upload_queries(const std::vector<DNSQuery>& queries);
    bool register_device();
    
    // Error handling
    void log_error(const std::string& message);
    void log_info(const std::string& message);
};

// Python bindings interface
extern "C" {
    // C interface for Python integration
    DNSMonitor* create_dns_monitor(const char* config_path);
    void destroy_dns_monitor(DNSMonitor* monitor);
    bool start_monitoring(DNSMonitor* monitor);
    void stop_monitoring(DNSMonitor* monitor);
    void get_statistics(DNSMonitor* monitor, uint64_t* total, uint64_t* dns, uint64_t* uploaded);
}

#endif // DNS_MONITOR_H
