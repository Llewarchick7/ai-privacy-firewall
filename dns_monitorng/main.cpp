#include "dns_monitor.h"
#include <iostream>
#include <signal.h>
#include <thread>
#include <chrono>

static DNSMonitor* g_monitor = nullptr;

void signal_handler(int signal) {
    if (g_monitor) {
        std::cout << "\nReceived signal " << signal << ", stopping monitor..." << std::endl;
        g_monitor->stop();
    }
}

int main(int argc, char* argv[]) {
    // Set up signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create configuration
    DeviceConfig config;
    config.device_id = "cpp_test_device";
    config.api_url = "http://localhost:8000/api";
    config.monitor_interface = (argc > 1) ? argv[1] : "eth0";
    config.upload_batch_size = 50;
    config.upload_interval_seconds = 10;
    
    std::cout << "Starting DNS Monitor on interface: " << config.monitor_interface << std::endl;
    
    // Create and initialize monitor
    DNSMonitor monitor(config);
    g_monitor = &monitor;
    
    if (!monitor.initialize()) {
        std::cerr << "Failed to initialize DNS monitor" << std::endl;
        return 1;
    }
    
    // Start monitoring
    monitor.start();
    
    // Print statistics every 30 seconds
    while (monitor.is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        
        if (monitor.is_running()) {
            auto stats = monitor.get_statistics();
            std::cout << "Stats - Total: " << stats.total_packets 
                     << ", DNS: " << stats.dns_packets
                     << ", Uploaded: " << stats.uploaded_queries
                     << ", Rate: " << stats.packets_per_second << " pps" << std::endl;
        }
    }
    
    std::cout << "DNS Monitor stopped" << std::endl;
    return 0;
}
