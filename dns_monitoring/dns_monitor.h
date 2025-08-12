/*
 * DNS Monitor - High-Performance Network Packet Capture & Analysis System
 *
 * This module implements a real-time DNS traffic monitoring system using:
 * - Raw packet capture via libpcap (network programming)
 * - Multi-threaded producer-consumer architecture
 * - Protocol stack parsing (Ethernet → IP → UDP → DNS)
 * - Thread-safe data structures for concurrent processing
 * - RESTful API integration for data upload
 * 
 * Architecture Overview:
 * [Network Interface] → [libpcap] → [Capture Thread] → [Queue] → [Upload Thread] → [Backend API]
 * 
 * Performance Features:
 * - Zero-copy packet processing where possible
 * - Batch uploads to minimize API calls
 * - Atomic statistics for lock-free monitoring
 * - BPF filtering in kernel space for efficiency
 */

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <string> // String manipulation
#include <vector> // Dynamic arrays for IP lists
#include <functional> // Function objects (if needed)
#include <memory> // Smart pointers for RAII
#include <thread> // Multi-threading support
#include <atomic> // Lock-free thread-safe counters
#include <queue> // FIFO queue for producer-consumer pattern
#include <mutex> // Thread synchronization primitives 

// Forward declarations to avoid including heavy libpcap headers
// This keeps compilation fast and reduces dependencies
struct pcap;
typedef struct pcap pcap_t; // Alias 

/*
 * DNSQuery - Core Data Structure for representing a DNS Transaction
 * 
 * Represents a single DNS transaction (query or response) captured from network traffic.
 * This structure bridges the gap between raw network packets and structured data
 * that can be analyzed for security threats and privacy concerns.
 * 
 * Memory Layout Considerations:
 * - Strings use std::string for automatic memory management
 * - Vector for response_ips handles multiple A records efficiently
 * - Fields ordered roughly by access frequency for cache efficiency
 */
struct DNSQuery {
    // Device & Network Context
    std::string client_id; // Unique id to refer to the client device (e.g., "office_router_01")
    std::string client_ip; // Source IP of client device (e.g., "192.168.1.100")
    std::string server_ip; // Source IP of DNS server responding (e.g., "8.8.8.8", "1.1.1.1")

    // DNS Protocol Fields
    std::string query_name; // Domain being resolved (e.g., "google.com", "malware.example")
    std::string query_type; // DNS record type (A, AAAA, MX, TXT, CNAME, etc.)
    uint16_t transaction_id; // Unique DNS transaction ID for matching queries with responses

    // Temporal & Response Data
    uint64_t timestamp; // Unix timestamp (seconds since epoch) for chronological ordering
    bool is_response; // false=query from client, true=response from server
    std::string response_code; // DNS response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)
    std::vector<std::string> response_ips; // Resolved IP addresses (multiple for load balancing)
};

/*
 * DeviceConfig - Configuration Management for DNS Monitoring Devices
 * 
 * This structure encapsulates all configuration parameters needed to deploy
 * a DNS monitor in various network environments. Supports both edge devices
 * (routers, IoT gateways) and dedicated monitoring appliances.
 * 
 * Configuration Sources:
 * - JSON config files
 * - Environment variables  
 * - Command line arguments
 * - Remote configuration management
 */
struct DeviceConfig {
    // Device Identity & Authentication - configuration parameters for interfacing with backend
    std::string device_id; // Unique device identifier (hostname, MAC, or UUID)
    std::string api_token; // Bearer token for backend API authentication
    
    // Network Configuration
    std::string api_url; // Backend API endpoint to send data to (e.g., "https://api.privacy-firewall.com")
    std::string monitor_interface; // Network interface to monitor (e.g., "eth0", "wlan0", "any")

    // Operational Parameters
    std::string log_level; // Log level (e.g., DEBUG, INFO, WARN, ERROR)
    double threat_threshold = 0.7; // AI confidence threshold for threat classification (0.0-1.0)
    
    // Performance Tuning
    int upload_batch_size = 100; // DNS queries per API batch (balance latency vs throughput)
    int upload_interval_seconds = 30; // Upload frequency (balance real-time vs bandwidth)
};

/*
 * DNSMonitor - High-Performance DNS Traffic Capture & Analysis Engine
 * 

 * 
 * This class implements a production-ready DNS monitoring system with the following
 * architectural components:
 * 
 * THREADING MODEL:
 * - Main Thread: Control, configuration, statistics
 * - Capture Thread: Raw packet capture via libpcap (high priority)
 * - Upload Thread: API communication (can be slower)
 * 
 * DATA FLOW:
 * Network → libpcap → BPF Filter → Capture Thread → Parse → Queue → Upload Thread → API
 * 
 * THREAD SAFETY:
 * - Atomic operations for statistics (lock-free)
 * - Mutex-protected queue for DNS data
 * - Immutable configuration after startup
 * 
 * PERFORMANCE OPTIMIZATIONS:
 * - BPF filtering in kernel space (only DNS packets reach userspace)
 * - Batch processing for API uploads
 * - Zero-copy packet parsing where possible
 * - Lock-free statistics collection
 */
class DNSMonitor {
private:
    // === PRIVATE DATA MEMBERS ===

    // === CORE CONFIGURATION ===
    DeviceConfig config_; // Immutable configuration (set at startup)
    
    // === PACKET CAPTURE INFRASTRUCTURE ===
    pcap_t* pcap_handle_; // libpcap session handle for packet capture
    std::atomic<bool> running_; // Thread-safe running state flag
    
    // === PRODUCER-CONSUMER PIPELINE ===
    // Thread-safe queue implementing producer-consumer pattern:
    // Producer: packet_capture_loop() adds parsed DNS queries
    // Consumer: upload_loop() removes and uploads batches
    std::queue<DNSQuery> query_queue_; // FIFO queue for DNS queries awaiting upload
    std::mutex queue_mutex_; // Protects queue from concurrent access
    
    // === BACKGROUND PROCESSING THREADS ===
    std::thread capture_thread_; // High-priority packet capture (must not block)
    std::thread upload_thread_; // Lower-priority API communication
    
    // === PERFORMANCE METRICS ===
    // Using atomic operations for lock-free statistics collection
    // These can be safely read/written from multiple threads
    std::atomic<uint64_t> total_packets_;    // All packets seen (for capture rate calculation)
    std::atomic<uint64_t> dns_packets_;      // DNS packets successfully parsed
    std::atomic<uint64_t> uploaded_queries_; // DNS queries successfully uploaded to backend

public:
    // === PUBLIC INTERFACE (PUBLIC MEMBER FUNCTIONS) ===


    // === LIFECYCLE MANAGEMENT ===
    explicit DNSMonitor(const DeviceConfig& config);  // Constructor - Initialize with configuration
    ~DNSMonitor(); // Destructor - Cleanup resources and stop threads
    
    // === MAIN CONTROL INTERFACE ===
    bool initialize(); // Setup libpcap, apply filters, prepare for capture
    void start(); // Start background threads and begin monitoring
    void stop(); // Gracefully stop all operations and cleanup
    bool is_running() const { return running_.load(); } // Thread-safe status check
    
    // === CONFIGURATION MANAGEMENT ===
    bool load_config(const std::string& config_path); // Load from JSON file
    void update_config(const DeviceConfig& new_config); // Hot-reload configuration
    
    // === PERFORMANCE MONITORING ===
    /*
     * Statistics Structure - Real-time Performance Metrics
     * 
     * Used for monitoring system health, debugging performance issues,
     * and capacity planning. All values are cumulative since startup.
     */
    struct Statistics {
        uint64_t total_packets;      // Total packets captured (all protocols)
        uint64_t dns_packets;        // DNS packets successfully parsed
        uint64_t uploaded_queries;   // DNS queries uploaded to backend
        double packets_per_second;   // Real-time capture rate (for performance tuning)
    };
    Statistics get_statistics() const;    // Thread-safe statistics retrieval
    
private:
    // === PRIVATE MEMBER FUNCTIONS (HELPER FUNCTIONS) ===

    // === CORE PROCESSING LOOPS ===
    /*
     * Background thread functions implementing the producer-consumer pattern.
     * These run continuously until stop() is called.
     */
    void packet_capture_loop(); // Producer: captures packets and parses DNS data
    void upload_loop(); // Consumer: uploads batched DNS queries to backend
    
    // === PACKET PROCESSING PIPELINE ===
    /*
     * Static callback required by libpcap's C API. Forwards to instance method.
     * user_data contains pointer to DNSMonitor instance.
     */
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet);
    
    /*
     * Core packet processing pipeline:
     * Raw Packet → Ethernet → IP → UDP → DNS → Structured Data
     * 
     * Validates packet headers at each layer and extracts DNS information.
     */
    void process_packet(const struct pcap_pkthdr* header, const u_char* packet);
    
    // === DNS PROTOCOL PARSING ===
    /*
     * DNS packet parsing functions handle the complex DNS wire format:
     * - Variable-length domain names with compression
     * - Multiple sections (questions, answers, authority, additional)
     * - Different record types (A, AAAA, MX, TXT, etc.)
     */
    bool parse_dns_packet(const u_char* packet, size_t packet_len, DNSQuery& query);
    std::string parse_dns_name(const u_char* packet, size_t packet_len, size_t& offset);
    std::string get_query_type_string(uint16_t qtype);   // Convert numeric type to string (1→"A")
    std::string get_response_code_string(uint8_t rcode); // Convert numeric code to string (0→"NOERROR")
    
    // === NETWORK UTILITIES ===
    std::string ip_to_string(uint32_t ip);    // Convert 32-bit IP to dotted decimal
    std::string get_device_id();              // Generate unique device identifier
    std::string get_local_ip();               // Get device's primary IP address
    std::string get_mac_address();            // Get device's MAC address for fingerprinting
    
    // === API COMMUNICATION ===
    /*
     * RESTful API integration for uploading DNS data to backend.
     * Uses libcurl for HTTP/HTTPS communication with proper error handling.
     */
    bool upload_queries(const std::vector<DNSQuery>& queries);  // Batch upload via HTTP POST
    bool register_device();                                     // Register device with backend
    
    // === LOGGING & ERROR HANDLING ===
    void log_error(const std::string& message);  // Error logging with timestamp
    void log_info(const std::string& message);   // Info logging with timestamp
};

/*
 * Python Integration Layer - C ABI for Cross-Language Interoperability
 * 
 * Provides a C-style interface that Python can call via ctypes or Cython.
 * This allows the high-performance C++ DNS monitor to be controlled from
 * Python applications while maintaining the performance benefits of native code.
 * 
 * Memory Management:
 * - Python calls create_dns_monitor() to allocate
 * - Python must call destroy_dns_monitor() to deallocate
 * - No exceptions cross the C boundary (all errors via return codes)
 * 
 * Thread Safety:
 * - Safe to call from Python threads
 * - All operations are internally synchronized
 */
extern "C" {
    // === LIFECYCLE MANAGEMENT ===
    DNSMonitor* create_dns_monitor(const char* config_path);    // Allocate and configure monitor
    void destroy_dns_monitor(DNSMonitor* monitor);             // Cleanup and deallocate
    
    // === CONTROL OPERATIONS ===
    bool start_monitoring(DNSMonitor* monitor);                // Initialize and start capture
    void stop_monitoring(DNSMonitor* monitor);                 // Stop capture and cleanup
    
    // === STATISTICS INTERFACE ===
    void get_statistics(DNSMonitor* monitor, uint64_t* total, uint64_t* dns, uint64_t* uploaded);
}

#endif // DNS_MONITOR_H
