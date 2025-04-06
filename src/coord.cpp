#include "tornado.hpp"
// #include "raylib-cpp.hpp"

int main() {
    // Initialize ENet
    if (enet_initialize() != 0) {
        std::cerr << "Failed to initialize ENet" << std::endl;
        return -1;
    }

    tornado::Coordinator coordinator(4848);
    
    if (!coordinator.initialize()) {
        std::cerr << "Failed to initialize coordinator" << std::endl;
        enet_deinitialize();
        return -1;
    }

    std::cout << "Coordinator started. Press Ctrl+C to exit." << std::endl;

    bool running = true;
    while (running) {
        coordinator.update();

        // Optional: Add any additional coordinator-specific logic here
        // For example, you might want to print statistics periodically
        
        // Handle shutdown gracefully
        // if (WindowShouldClose()) { // If using raylib window
        //     running = false;
        // }
    }

    coordinator.shutdown();
    enet_deinitialize();
    return 0;
}
