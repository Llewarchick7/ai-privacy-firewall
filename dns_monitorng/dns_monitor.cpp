#include "dns_monitor.h"
#include <pcap.h>
#include <iostream>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <curl/curl.h>
#include <json/json.h>
#include <ifaddrs.h>
#include <unistd.h>

// DNS header structure
struct DNSHeader {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
};

DNSMonitor::DNSMonitor(const DeviceConfig& config) 
    : config_(config), pcap_handle_(nullptr), running_(false),
      total_packets_(0), dns_packets_(0), uploaded_queries_(0) {
}

DNSMonitor::~DNSMonitor() {
    stop();
}

bool DNSMonitor::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open network interface for packet capture
    pcap_handle_ = pcap_open_live(
        config_.monitor_interface.c_str(),
        65536,  // snapshot length
        1,      // promiscuous mode
        1000,   // timeout (ms)
        errbuf
    );
    
    if (!pcap_handle_) {
        log_error("Failed to open interface " + config_.monitor_interface + ": " + errbuf);
        return false;
    }
    
    // Set filter for DNS traffic only
    struct bpf_program filter;
    if (pcap_compile(pcap_handle_, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log_error("Failed to compile filter: " + std::string(pcap_geterr(pcap_handle_)));
        return false;
    }
    
    if (pcap_setfilter(pcap_handle_, &filter) == -1) {
        log_error("Failed to set filter: " + std::string(pcap_geterr(pcap_handle_)));
        return false;
    }
    
    pcap_freecode(&filter);
    
    // Initialize curl for HTTP requests
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    log_info("DNS Monitor initialized on interface: " + config_.monitor_interface);
    return true;
}

void DNSMonitor::start() {
    if (running_.load()) {
        return;
    }
    
    running_.store(true);
    
    // Register device with backend
    register_device();
    
    // Start capture thread
    capture_thread_ = std::thread(&DNSMonitor::packet_capture_loop, this);
    
    // Start upload thread
    upload_thread_ = std::thread(&DNSMonitor::upload_loop, this);
    
    log_info("DNS Monitor started");
}

void DNSMonitor::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    
    // Stop packet capture
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }
    
    // Wait for threads to finish
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    if (upload_thread_.joinable()) {
        upload_thread_.join();
    }
    
    // Cleanup
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    curl_global_cleanup();
    
    log_info("DNS Monitor stopped");
}

void DNSMonitor::packet_capture_loop() {
    log_info("Starting packet capture loop");
    
    // Set thread name for debugging
    pthread_setname_np(pthread_self(), "DNSCapture");
    
    while (running_.load()) {
        int result = pcap_dispatch(pcap_handle_, 100, packet_handler, reinterpret_cast<u_char*>(this));
        
        if (result == -1) {
            log_error("Error in packet capture: " + std::string(pcap_geterr(pcap_handle_)));
            break;
        } else if (result == -2) {
            // pcap_breakloop was called
            break;
        }
        
        // Small yield to prevent 100% CPU usage
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    log_info("Packet capture loop ended");
}

void DNSMonitor::packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    DNSMonitor* monitor = reinterpret_cast<DNSMonitor*>(user_data);
    monitor->process_packet(header, packet);
}

void DNSMonitor::process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    total_packets_.fetch_add(1);
    
    // Parse Ethernet header
    struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    // Parse IP header
    struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
    if (ip_header->protocol != IPPROTO_UDP) {
        return;
    }
    
    // Parse UDP header
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4));
    
    // Check if it's DNS traffic (port 53)
    if (ntohs(udp_header->source) != 53 && ntohs(udp_header->dest) != 53) {
        return;
    }
    
    dns_packets_.fetch_add(1);
    
    // Parse DNS packet
    DNSQuery query;
    size_t dns_offset = sizeof(struct ether_header) + (ip_header->ihl * 4) + sizeof(struct udphdr);
    
    if (parse_dns_packet(packet + dns_offset, header->caplen - dns_offset, query)) {
        // Fill in additional information
        query.device_id = config_.device_id;
        query.client_ip = ip_to_string(ntohl(ip_header->saddr));
        query.server_ip = ip_to_string(ntohl(ip_header->daddr));
        query.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        // Add to queue for processing
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            query_queue_.push(query);
        }
    }
}

bool DNSMonitor::parse_dns_packet(const u_char* packet, size_t packet_len, DNSQuery& query) {
    if (packet_len < sizeof(DNSHeader)) {
        return false;
    }
    
    const DNSHeader* dns_header = reinterpret_cast<const DNSHeader*>(packet);
    
    query.transaction_id = ntohs(dns_header->transaction_id);
    query.is_response = (ntohs(dns_header->flags) & 0x8000) != 0;
    
    if (query.is_response) {
        query.response_code = get_response_code_string((ntohs(dns_header->flags) >> 8) & 0x0F);
    }
    
    // Parse questions section
    size_t offset = sizeof(DNSHeader);
    uint16_t questions = ntohs(dns_header->questions);
    
    if (questions > 0 && offset < packet_len) {
        query.query_name = parse_dns_name(packet, packet_len, offset);
        
        if (offset + 4 <= packet_len) {
            uint16_t qtype = ntohs(*reinterpret_cast<const uint16_t*>(packet + offset));
            query.query_type = get_query_type_string(qtype);
            offset += 4; // Skip qtype and qclass
        }
    }
    
    // Parse answers for responses
    if (query.is_response && ntohs(dns_header->answer_rrs) > 0) {
        // Skip over questions section first
        for (int i = 0; i < questions && offset < packet_len; i++) {
            parse_dns_name(packet, packet_len, offset); // Skip name
            offset += 4; // Skip qtype and qclass
        }
        
        // Parse answer section
        uint16_t answers = ntohs(dns_header->answer_rrs);
        for (int i = 0; i < answers && offset < packet_len; i++) {
            parse_dns_name(packet, packet_len, offset); // Skip name
            
            if (offset + 10 <= packet_len) {
                uint16_t rtype = ntohs(*reinterpret_cast<const uint16_t*>(packet + offset));
                offset += 8; // Skip type, class, TTL
                
                uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t*>(packet + offset));
                offset += 2;
                
                if (rtype == 1 && rdlength == 4 && offset + 4 <= packet_len) { // A record
                    uint32_t ip = *reinterpret_cast<const uint32_t*>(packet + offset);
                    query.response_ips.push_back(ip_to_string(ntohl(ip)));
                }
                
                offset += rdlength;
            }
        }
    }
    
    return !query.query_name.empty();
}

std::string DNSMonitor::parse_dns_name(const u_char* packet, size_t packet_len, size_t& offset) {
    std::string name;
    bool jumped = false;
    size_t original_offset = offset;
    
    while (offset < packet_len) {
        uint8_t len = packet[offset];
        
        if (len == 0) {
            offset++;
            break;
        } else if ((len & 0xC0) == 0xC0) {
            // Compression pointer
            if (offset + 1 >= packet_len) break;
            
            if (!jumped) {
                original_offset = offset + 2;
                jumped = true;
            }
            
            offset = ((len & 0x3F) << 8) | packet[offset + 1];
            continue;
        } else {
            // Regular label
            if (offset + 1 + len >= packet_len) break;
            
            if (!name.empty()) {
                name += ".";
            }
            
            name += std::string(reinterpret_cast<const char*>(packet + offset + 1), len);
            offset += len + 1;
        }
    }
    
    if (jumped) {
        offset = original_offset;
    }
    
    return name;
}

std::string DNSMonitor::get_query_type_string(uint16_t qtype) {
    switch (qtype) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        default: return std::to_string(qtype);
    }
}

std::string DNSMonitor::get_response_code_string(uint8_t rcode) {
    switch (rcode) {
        case 0: return "NOERROR";
        case 1: return "FORMERR";
        case 2: return "SERVFAIL";
        case 3: return "NXDOMAIN";
        case 4: return "NOTIMP";
        case 5: return "REFUSED";
        default: return std::to_string(rcode);
    }
}

std::string DNSMonitor::ip_to_string(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return std::string(inet_ntoa(addr));
}

void DNSMonitor::upload_loop() {
    log_info("Starting upload loop");
    
    while (running_.load()) {
        std::vector<DNSQuery> queries_to_upload;
        
        // Collect queries from queue
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            while (!query_queue_.empty() && queries_to_upload.size() < config_.upload_batch_size) {
                queries_to_upload.push_back(query_queue_.front());
                query_queue_.pop();
            }
        }
        
        // Upload if we have queries
        if (!queries_to_upload.empty()) {
            if (upload_queries(queries_to_upload)) {
                uploaded_queries_.fetch_add(queries_to_upload.size());
            }
        }
        
        // Wait before next upload
        std::this_thread::sleep_for(std::chrono::seconds(config_.upload_interval_seconds));
    }
    
    log_info("Upload loop ended");
}

bool DNSMonitor::upload_queries(const std::vector<DNSQuery>& queries) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }
    
    // Build JSON payload
    Json::Value json_array(Json::arrayValue);
    for (const auto& query : queries) {
        Json::Value json_query;
        json_query["device_id"] = query.device_id;
        json_query["query_name"] = query.query_name;
        json_query["query_type"] = query.query_type;
        json_query["client_ip"] = query.client_ip;
        json_query["server_ip"] = query.server_ip;
        json_query["timestamp"] = static_cast<int64_t>(query.timestamp);
        json_query["is_response"] = query.is_response;
        
        if (query.is_response) {
            json_query["response_code"] = query.response_code;
            if (!query.response_ips.empty()) {
                json_query["response_ip"] = query.response_ips[0];
            }
        }
        
        json_array.append(json_query);
    }
    
    Json::StreamWriterBuilder builder;
    std::string json_string = Json::writeString(builder, json_array);
    
    // Set curl options
    std::string url = config_.api_url + "/dns/dns-queries/batch";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_string.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_string.length());
    
    // Set headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    if (!config_.api_token.empty()) {
        std::string auth_header = "Authorization: Bearer " + config_.api_token;
        headers = curl_slist_append(headers, auth_header.c_str());
    }
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK || response_code != 200) {
        log_error("Upload failed: " + std::string(curl_easy_strerror(res)) + " (HTTP " + std::to_string(response_code) + ")");
        return false;
    }
    
    return true;
}

bool DNSMonitor::register_device() {
    // Implementation for device registration
    log_info("Device registration not yet implemented");
    return true;
}

DNSMonitor::Statistics DNSMonitor::get_statistics() const {
    static auto start_time = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
    
    Statistics stats;
    stats.total_packets = total_packets_.load();
    stats.dns_packets = dns_packets_.load();
    stats.uploaded_queries = uploaded_queries_.load();
    stats.packets_per_second = duration > 0 ? static_cast<double>(stats.total_packets) / duration : 0.0;
    
    return stats;
}

void DNSMonitor::log_error(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
}

void DNSMonitor::log_info(const std::string& message) {
    std::cout << "[INFO] " << message << std::endl;
}

// C interface for Python bindings
extern "C" {
    DNSMonitor* create_dns_monitor(const char* config_path) {
        DeviceConfig config;
        // Load config from file or use defaults
        config.device_id = "cpp_device_001";
        config.api_url = "http://localhost:8000/api";
        config.monitor_interface = "eth0";
        
        return new DNSMonitor(config);
    }
    
    void destroy_dns_monitor(DNSMonitor* monitor) {
        delete monitor;
    }
    
    bool start_monitoring(DNSMonitor* monitor) {
        if (!monitor->initialize()) {
            return false;
        }
        monitor->start();
        return true;
    }
    
    void stop_monitoring(DNSMonitor* monitor) {
        monitor->stop();
    }
    
    void get_statistics(DNSMonitor* monitor, uint64_t* total, uint64_t* dns, uint64_t* uploaded) {
        auto stats = monitor->get_statistics();
        *total = stats.total_packets;
        *dns = stats.dns_packets;
        *uploaded = stats.uploaded_queries;
    }
}
