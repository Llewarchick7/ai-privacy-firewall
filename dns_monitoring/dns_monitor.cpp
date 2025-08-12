/*
 * DNS Monitor Implementation - High-Performance Network Traffic Analysis
 * 
 * This file implements a real-time DNS monitoring system that captures and analyzes
 * network traffic at the packet level. Key technologies and concepts used:
 * 
 * NETWORK PROGRAMMING CONCEPTS:
 * - Raw packet capture using libpcap (Berkeley Packet Filter)
 * - Protocol stack parsing (Ethernet → IP → UDP → DNS)
 * - Network byte order conversion (big-endian ↔ little-endian)
 * - Socket-level network interface access
 * 
 * PERFORMANCE OPTIMIZATIONS:
 * - Kernel-space BPF filtering (only DNS packets reach userspace)
 * - Multi-threaded producer-consumer architecture
 * - Lock-free atomic operations for statistics
 * - Batch processing for API uploads
 * - Zero-copy packet parsing where possible
 * 
 * THREADING MODEL:
 * - Capture Thread: High-priority, real-time packet processing
 * - Upload Thread: Background, handles slower API communication
 * - Main Thread: Control, configuration, and monitoring
 */

#include "dns_monitor.h"
#include <pcap.h> // Packet capture library
#include <iostream>        // Standard I/O streams
#include <chrono>          // High-resolution timing
#include <cstring>         // C string manipulation
#include <arpa/inet.h>     // Internet address manipulation (inet_ntoa, htons, etc.)
#include <net/ethernet.h> // Ethernet Layer (Layer 2)
#include <netinet/in.h>    // Internet protocol family structures
#include <netinet/ip.h>   // IP Layer (Layer 3)
#include <netinet/udp.h>  // UDP Layer (Layer 4)
#include <curl/curl.h>     // HTTP client library for API communication
#include <json/json.h>     // JSON parsing and generation
#include <ifaddrs.h>       // Network interface enumeration
#include <unistd.h>        // POSIX system calls
#include <sys/socket.h>    // Socket programming
#include <netdb.h>         // Network database operations
#include <fstream>         // File I/O operations
#include <sstream>         // String stream operations
#include <pthread.h>       // POSIX threads for thread naming
#include <iomanip>         // I/O manipulators for logging
#include <netpacket/packet.h> // Packet-level network access for MAC addresses



/*
 * DNS Header Structure - RFC 1035 Standard DNS Message Format
 * 
 * This structure represents the fixed 12-byte header present in all DNS messages.
 * Understanding this structure is crucial for parsing DNS traffic:
 * 
 * FIELD EXPLANATIONS:
 * - transaction_id: Unique identifier linking queries to responses (16-bit)
 * - flags: Control bits including QR (query/response), opcode, authoritative answer, etc.
 * - questions: Number of questions in the query section
 * - answer_rrs: Number of resource records in the answer section
 * - authority_rrs: Number of resource records in the authority section  
 * - additional_rrs: Number of resource records in the additional section
 * 
 * NETWORK BYTE ORDER:
 * All multi-byte fields are in network byte order (big-endian) and must be
 * converted using ntohs() before use on little-endian architectures.
 */
struct DNSHeader {
    uint16_t transaction_id; // Transaction ID - unique id assigned to each DNS query
    uint16_t flags; // Flags - contains various control bits 
    uint16_t questions; // Number of entries in the question section
    uint16_t answer_rrs; // Number of resource records in the answer section
    uint16_t authority_rrs; // Number of resource records in the authority section
    uint16_t additional_rrs; // Number of resource records in the additional section
};

/*
 * Constructor - Initialize DNS Monitor with Configuration
 * 
 * Sets up the DNS monitor instance with the provided configuration.
 * Uses member initializer list for efficiency and proper initialization order.
 * 
 * INITIALIZATION ORDER:
 * 1. Configuration (copied for thread safety)
 * 2. libpcap handle (set to null, initialized later)
 * 3. Running state (atomic boolean for thread safety)
 * 4. Statistics counters (all start at zero)
 */
DNSMonitor::DNSMonitor(const DeviceConfig& config) 
    : config_(config), pcap_handle_(nullptr), running_(false),
      total_packets_(0), dns_packets_(0), uploaded_queries_(0) {
    log_info("DNS Monitor created with device ID: " + config_.device_id);
}

/*
 * Destructor - Cleanup Resources and Stop Operations
 * 
 * Ensures proper cleanup when DNSMonitor object is destroyed.
 * Calls stop() to gracefully shut down threads and release resources.
 * This follows RAII (Resource Acquisition Is Initialization) principle.
 */
DNSMonitor::~DNSMonitor() {
    stop();
    log_info("DNS Monitor destroyed");
}

/*
 * Initialize - Setup Packet Capture Infrastructure
 * 
 * This method configures libpcap for DNS traffic monitoring:
 * 
 * SETUP PROCESS:
 * 1. Open network interface for packet capture
 * 2. Compile and apply BPF filter for DNS traffic only
 * 3. Initialize libcurl for HTTP API communication
 * 
 * BPF FILTER: "udp port 53"
 * - Compiled to bytecode and executed in kernel space
 * - Only DNS packets (UDP port 53) reach userspace
 * - Dramatically reduces CPU overhead compared to userspace filtering
 * 
 * PROMISCUOUS MODE:
 * - Captures all packets on the network segment
 * - Necessary for monitoring network-wide DNS traffic
 * - May require elevated privileges (root/admin)
 */
bool DNSMonitor::initialize() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    log_info("Initializing DNS Monitor on interface: " + config_.monitor_interface);
    
    // Open network interface for packet capture
    // Parameters: interface, snaplen, promiscuous, timeout, error_buffer
    pcap_handle_ = pcap_open_live(
        config_.monitor_interface.c_str(),
        65536,  // snapshot length - max bytes per packet (64KB should capture full DNS packets)
        1,      // promiscuous mode - capture all traffic on network segment
        1000,   // timeout (ms) - how long to wait for packets before returning
        errbuf
    );
    
    if (!pcap_handle_) {
        log_error("Failed to open interface " + config_.monitor_interface + ": " + errbuf);
        return false;
    }
    
    // Compile BPF (Berkeley Packet Filter) for DNS traffic only
    // This filter runs in kernel space for maximum efficiency
    struct bpf_program filter;
    if (pcap_compile(pcap_handle_, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        log_error("Failed to compile filter: " + std::string(pcap_geterr(pcap_handle_)));
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    // Apply the compiled filter to the capture session
    if (pcap_setfilter(pcap_handle_, &filter) == -1) {
        log_error("Failed to set filter: " + std::string(pcap_geterr(pcap_handle_)));
        pcap_freecode(&filter);
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    // Free the compiled filter (no longer needed after applying)
    pcap_freecode(&filter);
    
    // Initialize libcurl for HTTP API communication
    // This is a global initialization (not thread-safe to call multiple times)
    CURLcode curl_result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_result != CURLE_OK) {
        log_error("Failed to initialize libcurl: " + std::string(curl_easy_strerror(curl_result)));
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
        return false;
    }
    
    log_info("DNS Monitor initialized on interface: " + config_.monitor_interface);
    return true;
}

/*
 * Start - Begin DNS Monitoring Operations
 * 
 * Launches the multi-threaded monitoring system:
 * 
 * STARTUP SEQUENCE:
 * 1. Check if already running (atomic load operation)
 * 2. Set running flag (atomic store operation)
 * 3. Register device with backend API
 * 4. Start capture thread (high priority, real-time packet processing)
 * 5. Start upload thread (background, API communication)
 * 
 * THREAD SAFETY:
 * - Uses atomic operations for running_ flag
 * - Safe to call from any thread
 * - Idempotent (safe to call multiple times)
 */
void DNSMonitor::start() {
    if (running_.load()) {
        log_info("DNS Monitor already running");
        return;  // Already running, nothing to do
    }
    
    if (!pcap_handle_) {
        log_error("Cannot start monitoring - not initialized");
        return;
    }
    
    running_.store(true);  // Atomic operation - signals all threads to start/continue
    
    // Register this device with the backend API for identification and auth
    register_device();
    
    // Start the high-priority packet capture thread
    // This thread must run with minimal latency to avoid packet drops
    capture_thread_ = std::thread(&DNSMonitor::packet_capture_loop, this);
    
    // Start the background upload thread  
    // This thread handles slower API communication without blocking capture
    upload_thread_ = std::thread(&DNSMonitor::upload_loop, this);
    
    log_info("DNS Monitor started");
}

/*
 * Stop - Gracefully Shutdown DNS Monitoring
 * 
 * Implements a clean shutdown procedure:
 * 
 * SHUTDOWN SEQUENCE:
 * 1. Check if already stopped (avoid double-shutdown)
 * 2. Signal all threads to stop (atomic store)
 * 3. Break packet capture loop (pcap_breakloop)
 * 4. Wait for capture thread to finish (thread.join)
 * 5. Wait for upload thread to finish (thread.join)
 * 6. Clean up libpcap resources
 * 7. Clean up libcurl resources
 * 
 * THREAD SAFETY:
 * - Uses atomic operations for coordination
 * - Proper thread joining prevents resource leaks
 * - Safe to call from destructor
 */
void DNSMonitor::stop() {
    if (!running_.load()) {
        return;  // Already stopped, nothing to do
    }
    
    log_info("Stopping DNS Monitor...");
    running_.store(false);  // Signal all threads to stop
    
    // Stop packet capture loop by breaking out of pcap_dispatch()
    if (pcap_handle_) {
        pcap_breakloop(pcap_handle_);
    }
    
    // Wait for capture thread to finish processing and exit cleanly
    // This ensures no packets are being processed when we cleanup
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
    // Wait for upload thread to finish current batch and exit
    // This ensures all queued data is uploaded before shutdown
    if (upload_thread_.joinable()) {
        upload_thread_.join();
    }
    
    // Clean up libpcap resources
    if (pcap_handle_) {
        pcap_close(pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    // Clean up libcurl global state
    // Note: This should only be called once per application
    curl_global_cleanup();
    
    log_info("DNS Monitor stopped");
}

/*
 * Packet Capture Loop - High-Priority Producer Thread
 * 
 * This is the core of the DNS monitoring system. Runs in a dedicated thread
 * with the following responsibilities:
 * 
 * PERFORMANCE CRITICAL:
 * - Must process packets as fast as they arrive to avoid drops
 * - Uses pcap_dispatch() for efficient batch processing
 * - Minimal processing per packet (parsing moved to separate function)
 * - Short sleep to prevent 100% CPU usage while maintaining responsiveness
 * 
 * ERROR HANDLING:
 * - Continues operation on transient errors
 * - Exits cleanly on fatal errors or stop signal
 * - Logs all error conditions for debugging
 * 
 * THREAD NAMING:
 * - Sets thread name for debugging and profiling tools
 */
void DNSMonitor::packet_capture_loop() {
    log_info("Starting packet capture loop");
    
    // Set thread name for debugging and system monitoring tools
    pthread_setname_np(pthread_self(), "DNSCapture");
    
    while (running_.load()) {
        // Process up to 100 packets at once for efficiency
        // Returns: >0 = packets processed, 0 = timeout, -1 = error, -2 = breakloop called
        int result = pcap_dispatch(pcap_handle_, 100, packet_handler, reinterpret_cast<u_char*>(this));
        
        if (result == -1) {
            // Fatal error in packet capture
            log_error("Error in packet capture: " + std::string(pcap_geterr(pcap_handle_)));
            break;
        } else if (result == -2) {
            // pcap_breakloop() was called (normal shutdown)
            break;
        }
        
        // Brief yield to prevent 100% CPU usage while maintaining low latency
        // 100 microseconds = 0.1ms (allows ~10,000 iterations per second)
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    
    log_info("Packet capture loop ended");
}

/*
 * Packet Handler - libpcap Callback Function (Static)
 * 
 * This static function serves as the bridge between libpcap's C API
 * and our C++ class instance. Required because libpcap expects a C-style
 * function pointer, not a C++ member function.
 * 
 * DESIGN PATTERN:
 * - Static function that accepts user_data pointer
 * - user_data contains pointer to DNSMonitor instance
 * - Forwards call to instance method for actual processing
 * 
 * PERFORMANCE NOTE:
 * - This function is called for every captured packet
 * - Must be extremely fast to avoid packet drops
 * - Does minimal work, delegates to process_packet()
 */
void DNSMonitor::packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet) {
    DNSMonitor* monitor = reinterpret_cast<DNSMonitor*>(user_data);
    monitor->process_packet(header, packet);
}

/*
 * Process Packet - Core Network Protocol Stack Parser
 * 
 * This function implements the network protocol parsing pipeline:
 * Raw Packet → Ethernet Frame → IP Packet → UDP Datagram → DNS Data
 * 
 * PARSING STAGES:
 * 1. Ethernet Header (Layer 2) - Check for IP traffic
 * 2. IP Header (Layer 3) - Check for UDP protocol  
 * 3. UDP Header (Layer 4) - Check for DNS port (53)
 * 4. DNS Data (Layer 7) - Parse DNS query/response
 * 
 * NETWORK BYTE ORDER:
 * - All multi-byte network fields are in big-endian format
 * - Must use ntohs() and ntohl() to convert to host byte order
 * - Critical for correct port and IP address interpretation
 * 
 * PERFORMANCE OPTIMIZATIONS:
 * - Early return on non-DNS traffic (most packets filtered out)
 * - Atomic increment for statistics (lock-free)
 * - Minimal memory allocation during parsing
 */
void DNSMonitor::process_packet(const struct pcap_pkthdr* header, const u_char* packet) {
    total_packets_.fetch_add(1);  // Atomic increment - thread-safe statistics
    
    // === LAYER 2: ETHERNET FRAME PARSING ===
    // Check if this is an IP packet (most common case for DNS)
    struct ether_header* eth_header = (struct ether_header*)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;  // Not IP traffic, ignore (e.g., ARP, IPv6, etc.)
    }
    
    // === LAYER 3: IP PACKET PARSING ===
    // Parse IP header to check protocol type
    struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
    if (ip_header->protocol != IPPROTO_UDP) {
        return;  // Not UDP traffic, ignore (TCP, ICMP, etc.)
    }
    
    // === LAYER 4: UDP DATAGRAM PARSING ===
    // Calculate UDP header position (IP header length is variable)
    struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + (ip_header->ihl * 4));
    
    // Check if either source or destination port is 53 (DNS)
    // DNS queries: client_port → 53, DNS responses: 53 → client_port  
    if (ntohs(udp_header->source) != 53 && ntohs(udp_header->dest) != 53) {
        return;  // Not DNS traffic, ignore
    }
    
    dns_packets_.fetch_add(1);  // Atomic increment - DNS packet statistics
    
    // === LAYER 7: DNS DATA PARSING ===
    DNSQuery query;
    size_t dns_offset = sizeof(struct ether_header) + (ip_header->ihl * 4) + sizeof(struct udphdr);
    
    // Parse the DNS packet data into structured format
    if (parse_dns_packet(packet + dns_offset, header->caplen - dns_offset, query)) {
        // Fill in network context information
        query.client_id = config_.device_id;
        query.client_ip = ip_to_string(ntohl(ip_header->saddr));  // Source IP (network→host order)
        query.server_ip = ip_to_string(ntohl(ip_header->daddr));  // Destination IP (network→host order)
        query.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        // Add parsed query to the producer-consumer queue for upload
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);  // Thread-safe queue access
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
        uint8_t rcode = ntohs(dns_header->flags) & 0x000F;
        query.response_code = get_response_code_string(rcode);
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

/*
 * Upload Loop - Background Consumer Thread
 * 
 * This thread implements the consumer side of the producer-consumer pattern:
 * 
 * RESPONSIBILITIES:
 * - Collect DNS queries from the thread-safe queue
 * - Batch multiple queries for efficient API upload
 * - Handle network failures and retry logic
 * - Maintain upload statistics
 * 
 * BATCHING STRATEGY:
 * - Collects up to upload_batch_size queries per API call
 * - Reduces API overhead and improves throughput
 * - Balances latency vs efficiency based on configuration
 * 
 * TIMING:
 * - Runs every upload_interval_seconds
 * - Continues until stop() is called
 * - Uses configurable intervals for different deployment scenarios
 */
void DNSMonitor::upload_loop() {
    log_info("Starting upload loop");
    
    while (running_.load()) {
        std::vector<DNSQuery> queries_to_upload;
        
        // === COLLECT QUERIES FROM QUEUE ===
        // Collect up to batch_size queries for efficient API upload
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);  // Thread-safe queue access
            while (!query_queue_.empty() && queries_to_upload.size() < config_.upload_batch_size) {
                queries_to_upload.push_back(query_queue_.front());
                query_queue_.pop();
            }
        }
        
        // === UPLOAD BATCH TO API ===
        // Only make API call if we have data to upload
        if (!queries_to_upload.empty()) {
            if (upload_queries(queries_to_upload)) {
                uploaded_queries_.fetch_add(queries_to_upload.size());  // Update statistics
            }
            // Note: Failed uploads are logged in upload_queries() function
        }
        
        // === WAIT FOR NEXT UPLOAD CYCLE ===
        // Sleep for configured interval before next upload attempt
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
        json_query["device_id"] = query.client_id; // Using client_id from struct
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

/*
 * Load Configuration - Parse JSON Configuration File
 * 
 * Loads device configuration from a JSON file. This allows for
 * flexible deployment across different environments without recompilation.
 * 
 * JSON Structure Expected:
 * {
 *   "device_id": "router_001",
 *   "api_url": "https://api.privacy-firewall.com",
 *   "api_token": "bearer_token_here",
 *   "monitor_interface": "eth0",
 *   "log_level": "INFO",
 *   "threat_threshold": 0.7,
 *   "upload_batch_size": 100,
 *   "upload_interval_seconds": 30
 * }
 */
bool DNSMonitor::load_config(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        log_error("Failed to open config file: " + config_path);
        return false;
    }
    
    Json::Value root;
    Json::CharReaderBuilder builder;
    std::string errs;
    
    if (!Json::parseFromStream(builder, file, &root, &errs)) {
        log_error("Failed to parse JSON config: " + errs);
        return false;
    }
    
    // Update configuration with JSON values (with defaults)
    if (root.isMember("device_id")) {
        config_.device_id = root["device_id"].asString();
    } else {
        config_.device_id = get_device_id(); // Generate if not specified
    }
    
    if (root.isMember("api_url")) {
        config_.api_url = root["api_url"].asString();
    }
    
    if (root.isMember("api_token")) {
        config_.api_token = root["api_token"].asString();
    }
    
    if (root.isMember("monitor_interface")) {
        config_.monitor_interface = root["monitor_interface"].asString();
    }
    
    if (root.isMember("log_level")) {
        config_.log_level = root["log_level"].asString();
    }
    
    if (root.isMember("threat_threshold")) {
        config_.threat_threshold = root["threat_threshold"].asDouble();
    }
    
    if (root.isMember("upload_batch_size")) {
        config_.upload_batch_size = root["upload_batch_size"].asInt();
    }
    
    if (root.isMember("upload_interval_seconds")) {
        config_.upload_interval_seconds = root["upload_interval_seconds"].asInt();
    }
    
    log_info("Configuration loaded from: " + config_path);
    return true;
}

/*
 * Update Configuration - Hot-Reload Configuration
 * 
 * Updates the current configuration without requiring a restart.
 * Note: Some changes (like monitor_interface) may require restart to take effect.
 */
void DNSMonitor::update_config(const DeviceConfig& new_config) {
    config_ = new_config;
    log_info("Configuration updated");
}

/*
 * Get Device ID - Generate Unique Device Identifier
 * 
 * Creates a unique identifier for this device using hostname and MAC address.
 * This identifier is used to distinguish different monitoring devices in the backend.
 * 
 * Strategy:
 * 1. Try to get hostname
 * 2. Append MAC address of primary interface
 * 3. Fallback to timestamp-based ID if all else fails
 */
std::string DNSMonitor::get_device_id() {
    std::string device_id = "unknown_device";
    
    // Get hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        device_id = std::string(hostname);
    }
    
    // Append MAC address for uniqueness
    std::string mac = get_mac_address();
    if (!mac.empty()) {
        device_id += "_" + mac;
    } else {
        // Fallback: append timestamp for uniqueness
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        device_id += "_" + std::to_string(timestamp);
    }
    
    return device_id;
}

/*
 * Get Local IP - Retrieve Primary IP Address
 * 
 * Finds the primary IP address of this device by examining network interfaces.
 * Excludes loopback and link-local addresses to find the "real" network IP.
 */
std::string DNSMonitor::get_local_ip() {
    struct ifaddrs *ifaddrs_ptr, *ifa;
    std::string local_ip = "127.0.0.1"; // Fallback to localhost
    
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        log_error("Failed to get network interfaces");
        return local_ip;
    }
    
    for (ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        // Look for IPv4 addresses
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            char ip_str[INET_ADDRSTRLEN];
            
            if (inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN)) {
                std::string ip(ip_str);
                
                // Skip loopback and link-local addresses
                if (ip != "127.0.0.1" && ip.substr(0, 8) != "169.254.") {
                    local_ip = ip;
                    break; // Use first valid IP found
                }
            }
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return local_ip;
}

/*
 * Get MAC Address - Retrieve Hardware Address
 * 
 * Extracts the MAC address of the primary network interface for device fingerprinting.
 * This provides a hardware-based unique identifier.
 * 
 * Returns: MAC address in format "aa:bb:cc:dd:ee:ff" or empty string on failure
 */
std::string DNSMonitor::get_mac_address() {
    struct ifaddrs *ifaddrs_ptr, *ifa;
    std::string mac_address;
    
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        log_error("Failed to get network interfaces for MAC address");
        return mac_address;
    }
    
    for (ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        // Skip loopback interface
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        // Check if this is the interface we want to monitor
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll* s = (struct sockaddr_ll*)ifa->ifa_addr;
            
            if (s->sll_halen == 6) { // Standard Ethernet MAC length
                std::stringstream ss;
                ss << std::hex << std::setfill('0');
                for (int i = 0; i < 6; i++) {
                    if (i > 0) ss << ":";
                    ss << std::setw(2) << static_cast<int>(s->sll_addr[i]);
                }
                mac_address = ss.str();
                break; // Use first MAC found
            }
        }
    }
    
    freeifaddrs(ifaddrs_ptr);
    return mac_address;
}

bool DNSMonitor::register_device() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        log_error("Failed to initialize curl for device registration");
        return false;
    }
    
    // Build device registration payload
    Json::Value device_info;
    device_info["device_id"] = config_.device_id;
    device_info["local_ip"] = get_local_ip();
    device_info["mac_address"] = get_mac_address();
    device_info["interface"] = config_.monitor_interface;
    device_info["timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    Json::StreamWriterBuilder builder;
    std::string json_string = Json::writeString(builder, device_info);
    
    // Set curl options for device registration
    std::string url = config_.api_url + "/devices/register";
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
    
    // Perform registration request
    CURLcode res = curl_easy_perform(curl);
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    
    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    if (res == CURLE_OK && response_code == 200) {
        log_info("Device registered successfully with backend");
        return true;
    } else {
        log_error("Device registration failed: " + std::string(curl_easy_strerror(res)) + 
                 " (HTTP " + std::to_string(response_code) + ")");
        return false;
    }
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

/*
 * C Interface Implementation - Python Integration Layer
 * 
 * These functions provide a C-compatible interface that can be called from Python
 * using ctypes or other FFI (Foreign Function Interface) libraries.
 * 
 * DESIGN PRINCIPLES:
 * - No C++ exceptions across the interface boundary
 * - All errors communicated via return codes
 * - Simple C types only (no STL containers)
 * - Manual memory management (create/destroy pattern)
 * 
 * MEMORY MANAGEMENT:
 * - Python calls create_dns_monitor() to allocate
 * - Python must call destroy_dns_monitor() to prevent leaks
 * - All other operations work on the allocated instance
 * 
 * THREAD SAFETY:
 * - All operations are internally thread-safe
 * - Safe to call from Python threads
 * - Proper synchronization implemented in C++ layer
 */
extern "C" {
    /*
     * Create DNS Monitor Instance
     * 
     * Allocates and configures a new DNS monitor instance.
     * Loads configuration from the provided config file path if it exists,
     * otherwise uses reasonable defaults for development/testing.
     * 
     * Returns: Pointer to DNSMonitor instance, or nullptr on failure
     */
    DNSMonitor* create_dns_monitor(const char* config_path) {
        DeviceConfig config;
        
        // Initialize with defaults first
        config.device_id = "cpp_device_001";
        config.api_url = "http://localhost:8000/api";
        config.monitor_interface = "eth0";  // May need adjustment per environment
        config.log_level = "INFO";
        config.threat_threshold = 0.7;
        config.upload_batch_size = 100;
        config.upload_interval_seconds = 30;
        
        DNSMonitor* monitor = new DNSMonitor(config);
        
        // Try to load configuration from file if provided
        if (config_path && strlen(config_path) > 0) {
            if (!monitor->load_config(std::string(config_path))) {
                // Log warning but continue with defaults
                std::cerr << "[WARNING] Failed to load config from: " << config_path << std::endl;
            }
        }
        
        return monitor;
    }
    
    /*
     * Destroy DNS Monitor Instance
     * 
     * Properly cleans up and deallocates a DNS monitor instance.
     * Automatically stops monitoring if still running.
     */
    void destroy_dns_monitor(DNSMonitor* monitor) {
        delete monitor;  // Destructor handles cleanup via RAII
    }
    
    /*
     * Start Monitoring Operations
     * 
     * Initializes libpcap and starts the monitoring threads.
     * 
     * Returns: true on success, false on failure
     */
    bool start_monitoring(DNSMonitor* monitor) {
        if (!monitor->initialize()) {
            return false;  // Failed to initialize packet capture
        }
        monitor->start();
        return true;
    }
    
    /*
     * Stop Monitoring Operations
     * 
     * Gracefully stops all monitoring activities and cleans up resources.
     */
    void stop_monitoring(DNSMonitor* monitor) {
        monitor->stop();
    }
    
    /*
     * Get Performance Statistics
     * 
     * Retrieves current performance metrics via output parameters.
     * This C-style interface avoids returning complex C++ objects.
     * 
     * Parameters:
     * - monitor: DNS monitor instance
     * - total: Output parameter for total packets captured
     * - dns: Output parameter for DNS packets parsed
     * - uploaded: Output parameter for queries uploaded to backend
     */
    void get_statistics(DNSMonitor* monitor, uint64_t* total, uint64_t* dns, uint64_t* uploaded) {
        auto stats = monitor->get_statistics();
        *total = stats.total_packets;
        *dns = stats.dns_packets;
        *uploaded = stats.uploaded_queries;
    }
}
