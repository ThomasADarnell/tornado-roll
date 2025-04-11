// Licensing at end of file
#ifndef tornadoroll
#define tornadoroll

// Only external include user needs!
#include <enet/enet.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <random>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <unordered_map>
#include <regex>
#include <chrono>
#include <arpa/inet.h>
#include <netdb.h>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <cstring>

#define MAX_PLAYERS 4
#define sessionId_LENGTH 10
#define DEFAULT_PORT 4848
#define CLIENT_TIMEOUT 60000
#define COORD_TIMEOUT 30000
namespace tornado {
    template<typename T>
    struct NetworkData {
        virtual void serialize(std::vector<uint8_t>& buffer) const = 0;
        virtual void deserialize(const uint8_t* data, size_t size) = 0;
        virtual ~NetworkData() = default;
    };

    enum class CoordMsgType : uint8_t {
        PeerList,
        NewPeer,
        CoordDisconnect,
        ClientDisconnect,
        AssignHost,
        GetHost,
        PromoteHost
    };

    struct CoordinatorMessage {
        CoordMsgType type;
        std::vector<uint8_t> data;

        template<typename T>
        void write(const T& value) {
            size_t oldSize = data.size();
            data.resize(oldSize + sizeof(T));
            memcpy(data.data() + oldSize, &value, sizeof(T));
        }

        ENetPacket* createPacket(uint32_t flags = ENET_PACKET_FLAG_RELIABLE) {
            std::vector<uint8_t> packet_data;
            packet_data.reserve(1 + data.size());
            
            packet_data.push_back(static_cast<uint8_t>(type));
            
            packet_data.insert(
                packet_data.end(), 
                data.begin(), 
                data.end()
            );

            return enet_packet_create(
                packet_data.data(),
                packet_data.size(),
                flags
            );
        }
    };

    class MessageReader {
        private:
            const uint8_t* buffer;
            size_t size;
            size_t cursor;
        
        public:
            MessageReader(const ENetPacket* packet) 
                : buffer(packet->data), 
                  size(packet->dataLength), 
                  cursor(0)
            {}
        
            MessageReader(const uint8_t* data, size_t length) 
                : buffer(data), 
                  size(length), 
                  cursor(0)
            {}
        
            template<typename T>
            T read() {
                if (cursor + sizeof(T) > size) {
                    throw std::out_of_range("Buffer overflow in MessageReader");
                }
                T value;
                memcpy(&value, buffer + cursor, sizeof(T));
                cursor += sizeof(T);
                return value;
            }
        
            bool hasMore() const {
                return cursor < size;
            }
    };

    template<typename K, typename V>
    class ThreadSafeMap {
    private:
        std::map<K, V> map;
        mutable std::shared_mutex mutex;

    public: 
        void insert(const K& key, const V& value) {
            std::unique_lock<std::shared_mutex> lock(mutex);
            map[key] = value;
        }

        bool find(const K& key, V& value) const {
            std::shared_lock<std::shared_mutex> lock(mutex);
            auto it = map.find(key);
            if (it != map.end()) {
                value = it->second; 
                return true;
            }
            return false;
        }

        V get(const K& key) const {
            std::shared_lock<std::shared_mutex> lock(mutex);
            auto it = map.find(key);
            if (it != map.end()) {
                return it->second;
            }
            return V{}; 
        }

        bool contains(const K& key) const {
            std::shared_lock<std::shared_mutex> lock(mutex);
            return map.find(key) != map.end();
        }

        bool remove(const K& key) {
            std::unique_lock<std::shared_mutex> lock(mutex);
            return map.erase(key) > 0;
        }

        template<typename Callback>
        void forEach(Callback c) const {
            std::shared_lock<std::shared_mutex> lock(mutex);
            for (const auto& [key, value] : map) {
                c(key, value);
            }
        }

        template<typename Callback>
        bool modifyIf(const K& key, Callback modifier) {
            std::unique_lock<std::shared_mutex> lock(mutex);
            auto it = map.find(key);
            if (it != map.end()) {
                modifier(it->second);
                return true;
            }
            return false;
        }
    };


    struct IceServer {
        enum class Type{
            STUN,
            //TURN // adding turn later
        };

        std::string hostname;
        uint16_t port;
        Type type;
        // std::string user; // irrelevant
        // std::string cert; // ditto for now

        IceServer(const std::string& host, uint16_t p) 
        : hostname(host), port(p), type(Type::STUN) {};
    };

    class IceConfiguration {
        public:
            std::vector<IceServer> servers;
        
            static IceConfiguration DefaultConfig() {
                IceConfiguration config;
                config.servers = { // free stun servers
                    IceServer("stun.l.google.com", 19302),
                    IceServer("stun1.l.google.com", 19302),
                    IceServer("stun2.l.google.com", 19302)
                };
                return config;
            }
        
            void addStunServer(const std::string& hostname, uint16_t port) {
                servers.emplace_back(hostname, port);
            }
        };
        
        struct IceCandidate {
            ENetAddress address;
            bool valid;
        
            IceCandidate() : valid(false) {}
            IceCandidate(const ENetAddress& addr) : address(addr), valid(true) {}
        };
        
        class IceAgent {
        public:
            enum class GatheringState {
                NEW,
                GATHERING,
                COMPLETE
            };
        
        private:
            IceConfiguration config;
            ENetHost* host;
            IceCandidate localCandidate;
            IceCandidate serverReflexiveCandidate;
            GatheringState state;
        
        public:
            IceAgent(const IceConfiguration& cfg) 
                : config(cfg), host(nullptr), state(GatheringState::NEW) {}
        
            ~IceAgent() {
                if (host) enet_host_destroy(host);
            }
        
            bool initialize() {
                if (host) return false;
        
                host = enet_host_create(nullptr, 1, 1, 0, 0);
                if (!host) return false;
        
                ENetAddress localAddr;
                localAddr.host = host->address.host;
                localAddr.port = host->address.port;
                localCandidate = IceCandidate(localAddr);
        
                return true;
            }
        
            bool gatherCandidates() {
                if (!host || state == GatheringState::GATHERING) return false;
        
                state = GatheringState::GATHERING;
                
                for (const auto& server : config.servers) {
                    if (queryStunServer(server)) {
                        state = GatheringState::COMPLETE;
                        return true;
                    }
                }
        
                state = GatheringState::COMPLETE;
                return false;
            }
        
            IceCandidate getLocalCandidate() const { return localCandidate; }
            IceCandidate getServerReflexiveCandidate() const { return serverReflexiveCandidate; }
            GatheringState getState() const { return state; }
        
        private:
            bool queryStunServer(const IceServer& server) {
                ENetAddress serverAddr;
                if (enet_address_set_host(&serverAddr, server.hostname.c_str()) < 0) {
                    return false;
                }
                serverAddr.port = server.port;
        
                ENetPeer* peer = enet_host_connect(host, &serverAddr, 1, 0);
                if (!peer) return false;
        
                ENetEvent event;
                auto start = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
                    while (enet_host_service(host, &event, 100) > 0) {
                        if (event.type == ENET_EVENT_TYPE_CONNECT) {
                            serverReflexiveCandidate = IceCandidate(event.peer->address);
                            enet_peer_disconnect_now(peer, 0);
                            return true;
                        }
                    }
                }
        
                enet_peer_reset(peer);
                return false;
            }
        };
        
        class P2PSession {
        private:
            std::unique_ptr<IceAgent> iceAgent;
            ENetHost* host;
            ENetPeer* peer;
            bool connected;
        
        public:
            P2PSession(const IceConfiguration& config = IceConfiguration::DefaultConfig())
                : host(nullptr), peer(nullptr), connected(false) {
                iceAgent = std::make_unique<IceAgent>(config);
            }
        
            ~P2PSession() {
                if (host) enet_host_destroy(host);
            }
        
            bool initialize() {
                if (!iceAgent->initialize()) return false;
                return true;
            }
        
            bool gatherCandidates() {
                return iceAgent->gatherCandidates();
            }
        
            bool connectToPeer(const ENetAddress& peerAddr) {
                if (iceAgent->getState() != IceAgent::GatheringState::COMPLETE) {
                    return false;
                }
        
                auto srflxCandidate = iceAgent->getServerReflexiveCandidate();
                if (srflxCandidate.valid && tryConnection(peerAddr)) {
                    return true;
                }
        
                auto localCandidate = iceAgent->getLocalCandidate();
                if (localCandidate.valid && tryConnection(peerAddr)) {
                    return true;
                }
        
                return false;
            }
        
        private:
            bool tryConnection(const ENetAddress& remoteAddr) {
                if (host) enet_host_destroy(host);
                
                host = enet_host_create(nullptr, 1, 1, 0, 0);
                if (!host) return false;
        
                peer = enet_host_connect(host, &remoteAddr, 2, 0);
                if (!peer) return false;
        
                ENetEvent event;
                auto start = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - start < std::chrono::seconds(5)) {
                    while (enet_host_service(host, &event, CLIENT_TIMEOUT) > 0) {
                        if (event.type == ENET_EVENT_TYPE_CONNECT) {
                            connected = true;
                            return true;
                        }
                    }
                }
        
                enet_peer_reset(peer);
                return false;
            }
        };

    enum class MessageType {
        CONNECT,
        DISCONNECT,
        HOST_SESSION,
        JOIN_SESSION,
        LEAVE_SESSION,
        DATA,
        PING
    };

    struct NetworkMessage {
        MessageType type;
        std::vector<uint8_t> data;
    };

    struct Session {
        uint32_t sessionId;
        ENetPeer* host;
        std::vector<ENetPeer*> clients;
        unsigned int numClients;
    };

    class Coordinator {
    private:
        ENetHost* server;
        uint16_t port;
        std::unordered_map<uint32_t, Session> sessions;
        bool initialized;

    public:
        Coordinator(uint16_t port = 4848) : port(port), initialized(false), server(nullptr) {}
        ~Coordinator() { shutdown(); }

        bool initialize() {            
            ENetAddress hostAddress;
            hostAddress.host = ENET_HOST_ANY;
            hostAddress.port = port;
            server = enet_host_create(&hostAddress, 100, 2, 0, 0);
            if (!server) return false;
            std::cout << "Listening on port " << port << std::endl;
            initialized = true;
            return true;
        }

        void shutdown() {
            if (server) {
                enet_host_destroy(server);
                server = nullptr;
            }
            initialized = false;
        }

        void update() {
            if (!initialized) return;

            ENetEvent event;
            if (enet_host_service(server, &event, COORD_TIMEOUT) > 0) {
                char ip[40];
			    enet_address_get_host_ip(&event.peer->address, ip, sizeof(ip));
                switch (event.type) {
                    case ENET_EVENT_TYPE_CONNECT:
                        handleClientConnect(event);
                        break;
                    case ENET_EVENT_TYPE_RECEIVE:
                        handleMessage(event);
                        enet_packet_destroy(event.packet);
                        break;
                    case ENET_EVENT_TYPE_DISCONNECT:
                        handleClientDisconnect(event);
                        break;
                    case ENET_EVENT_TYPE_NONE:
                        //TODO: handle failed connect
                        break;
                }
            }
        }

    private:
        void updateHostConnections(Session& ses, ENetPeer* n, bool explicitlyDisconnecting = false){
            bool isDisconnecting = (n->state == ENET_PEER_STATE_DISCONNECTING || n->state == ENET_PEER_STATE_DISCONNECTED || explicitlyDisconnecting);

            if (isDisconnecting) {
                auto it = std::find(ses.clients.begin(), ses.clients.end(), n);
                if (it != ses.clients.end()) {
                    ses.clients.erase(it);
                    ses.numClients--;
                }
            } else {
                if (std::find(ses.clients.begin(), ses.clients.end(), n) == ses.clients.end()) {
                    ses.clients.emplace_back(n);
                    ses.numClients++;
                }
            }

            CoordinatorMessage msg;
            msg.type = CoordMsgType::PeerList;
            msg.write(ses.clients.size());
            for(const auto& peer : ses.clients){
                msg.write(peer->address.host);
                msg.write(peer->address.port);
            }
            ENetPacket* updatePack = msg.createPacket();
            enet_peer_send(ses.host, 0, updatePack);
            return;
        };
        
        uint32_t randomSessionId() {
            using std::chrono::high_resolution_clock;
            static thread_local std::mt19937 rng(
                static_cast<unsigned int>(high_resolution_clock::now().time_since_epoch().count()));
            std::uniform_int_distribution<uint32_t> uniform_dist; 
            return uniform_dist(rng);
        };
        
        void handleClientConnect(ENetEvent& event) {
            CoordinatorMessage msg;
            bool assignedToSession = false;
            for(auto& [id, session] : sessions) {
                if(session.numClients < MAX_PLAYERS) {
                    msg.type = CoordMsgType::GetHost;
                    msg.write(static_cast<uint32_t>(session.host->address.host));
                    msg.write(static_cast<uint16_t>(session.host->address.port));
                    ENetPacket* packetHostLoc = msg.createPacket();
                    if(enet_peer_send(event.peer, 0, packetHostLoc) == 0) {
                        updateHostConnections(session, event.peer, false); 
                        assignedToSession = true;
                    } else {
                        std::cerr << "Unable to send packet containing host " << session.host->address.host << " to peer " << event.peer << ". Referenced session ID: " << session.sessionId << std::endl;
                        enet_packet_destroy(packetHostLoc); 
                    }
                    break;
                }
            }

            if (!assignedToSession) {
                msg.type = CoordMsgType::AssignHost;
                auto id = randomSessionId(); // Use new randomSessionId
                msg.write(id); // Send the new session ID to the host
                ENetPacket* packetAssignHost = msg.createPacket();
                if(enet_peer_send(event.peer, 0, packetAssignHost) == 0){
                    Session newSession;
                    newSession.sessionId = id;
                    newSession.host = event.peer;
                    newSession.numClients = 1; // Start with 1 client (the host)
                    // newSession.clients is initially empty as host doesn't list itself
                    sessions[id] = newSession;
                    std::cout << "Assigned peer " << event.peer << " as host for new session " << id << std::endl;
                    // No need to destroy packetAssignHost here
                } else {
                    std::cerr << "Unable to set " << event.peer << " as host.\n";
                    enet_packet_destroy(packetAssignHost); // Destroy if send failed
                }
            }
        }


        void handleClientDisconnect(ENetEvent& event) {
            std::cout << "Connection closed from " << event.peer << std::endl;
            
            for(auto& [sessionId, session] : sessions) {
                if(session.host == event.peer) {
                    std::cout << "Host disconnected from session " << sessionId << std::endl;
                    
                    if(!session.clients.empty()) {
                        ENetPeer* newHost = session.clients[0];
                        session.clients.erase(session.clients.begin());
                        session.host = newHost;
        
                        CoordinatorMessage hostMsg;
                        hostMsg.type = CoordMsgType::PromoteHost;
                        hostMsg.write(static_cast<uint32_t>(session.clients.size()));
                        for(const auto& client : session.clients) {
                            hostMsg.write(client->address.host);
                            hostMsg.write(client->address.port);
                        }
                        ENetPacket* hostPacket = hostMsg.createPacket();
                        enet_peer_send(newHost, 0, hostPacket);
        
                        CoordinatorMessage clientMsg;
                        clientMsg.type = CoordMsgType::GetHost;
                        clientMsg.write(newHost->address.host);
                        clientMsg.write(newHost->address.port);
                        
                        for(const auto& client : session.clients) {
                            ENetPacket* clientPacket = clientMsg.createPacket(); 
                            enet_peer_send(client, 0, clientPacket);
                        }
        
                        session.numClients--;
                    } else {
                        sessions.erase(sessionId);
                    }
                    return;
                }
        
                auto clientIt = std::find(session.clients.begin(), session.clients.end(), event.peer);
                if(clientIt != session.clients.end()) {
                    std::cout << "Client disconnected from session " << sessionId << std::endl;
                    session.clients.erase(clientIt);
                    session.numClients--;
        
                    CoordinatorMessage msg;
                    msg.type = CoordMsgType::ClientDisconnect;
                    msg.write(event.peer->address.host);
                    msg.write(event.peer->address.port);
                    ENetPacket* packet = msg.createPacket();
                    enet_peer_send(session.host, 0, packet); 
                    return;
                }
            }
        }

        void handleMessage(ENetEvent& event) {
            std::cout << "Data received from " << event.peer << " of size " << event.packet->dataLength << std::endl;
        }
    };

    class Client {
        private:
            struct SyncPacket {
                uint32_t sequence;
                uint32_t dataType;
                std::vector<uint8_t> payload;
            };
    
            std::mutex sync_mutex;
            uint32_t sequence_counter = 0;
            std::unordered_map<uint32_t, std::function<void(const uint8_t*, size_t)>> data_handlers;
            std::string coordIp;
            ENetHost* cli;
            ENetPeer* coordinatorPeer;
            ENetHost* self;
            std::vector<ENetPeer*> remote_peers;
            bool isHost;
            bool initialized;
            uint32_t sessionId;
            std::string local_id;
            IceConfiguration ice_config;
    
        public:
            std::function<void(const std::vector<uint8_t>&)> on_data_received;
    
            Client(const std::string& coordIp, IceConfiguration config = IceConfiguration());
            Client(const char* coordIp, IceConfiguration config = IceConfiguration());
            ~Client();
    
            template<typename T>
            using UpdateCallback = std::function<void(const T&)>;
    
            template<typename T>
            uint32_t register_sync_type(UpdateCallback<T> callback) {
                static uint32_t type_counter = 0;
                uint32_t type_id = ++type_counter;
                
                data_handlers[type_id] = [callback](const uint8_t* data, size_t size) {
                    T value;
                    if constexpr (std::is_base_of_v<NetworkData<T>, T>) {
                        value.deserialize(data, size);
                    } else {
                        memcpy(&value, data, std::min(size, sizeof(T)));
                    }
                    callback(value);
                };
                
                return type_id;
            }
    
            template<typename T>
            void broadcast_data(uint32_t type_id, const T& data) {
                if (!is_session_host()) return;
                
                std::lock_guard<std::mutex> lock(sync_mutex);
                
                std::vector<uint8_t> buffer;
                buffer.resize(sizeof(uint32_t) * 2);
                
                memcpy(buffer.data(), &type_id, sizeof(uint32_t));
                uint32_t seq = ++sequence_counter;
                memcpy(buffer.data() + sizeof(uint32_t), &seq, sizeof(uint32_t));
                
                if constexpr (std::is_base_of_v<NetworkData<T>, T>) {
                    data.serialize(buffer);
                } else {
                    size_t offset = buffer.size();
                    buffer.resize(offset + sizeof(T));
                    memcpy(buffer.data() + offset, &data, sizeof(T));
                }
                
                std::cout << "Broadcasting to " << remote_peers.size() << " peers" << std::endl;
                for (const auto& peer : remote_peers) {
                    if (peer) {
                        ENetPacket* packet = enet_packet_create(
                            buffer.data(),
                            buffer.size(),
                            ENET_PACKET_FLAG_RELIABLE
                        );
                        enet_peer_send(peer, 1, packet);
                    }
                }
            }
                
            // Method declarations
            bool initialize();
            void shutdown();
            bool connect_to_coordinator();
            void update();
            bool host_session();
            bool join_session(uint32_t sessionId);
            bool leave_session();
            void disconnect();
            
            // Utility method declarations
            const std::vector<ENetPeer*>& get_remote_peers() const;
            bool is_session_host() const;
            bool is_connected() const;
            uint32_t get_sessionId() const;
            void send_to_all_peers(const void* data, size_t dataLength, bool reliable = true);
            void send_to_host(const void* data, size_t dataLength, bool reliable = true);
    
        private:
            // Private method declarations
            std::string randomId(size_t length);
            void handleConnect(ENetEvent& event);
            void handleDisconnect(ENetEvent& event);
            void handleMessage(ENetEvent& event, ENetPacket* packet);
            void handle_sync_packet(const uint8_t* data, size_t size);
        };
        // Client class implementations
        inline Client::Client(const std::string& coordIp, IceConfiguration config)
            : coordIp(coordIp), cli(nullptr), coordinatorPeer(nullptr), self(nullptr), 
              isHost(false), initialized(false), sessionId(0), ice_config(config) {}
    
        inline Client::Client(const char* coordIp, IceConfiguration config)
            : Client(std::string(coordIp), config) {}
    
        inline Client::~Client() {
            shutdown();
        }
    
        inline bool Client::initialize() {
            std::cout << "Initializing client..." << std::endl;
            local_id = randomId(6);
            
            ENetAddress hostAddress;
            hostAddress.host = ENET_HOST_ANY;
            hostAddress.port = 0;
            std::cout << "Creating host on any address..." << std::endl;
            
            self = enet_host_create(&hostAddress, 10, 2, 0, 0);
            if(!self) {
                std::cerr << "Failed to create ENet host" << std::endl;
                return false;
            }
            std::cout << "ENet host created successfully" << std::endl;
            
            initialized = true;
            return true;
        }
    
        inline void Client::shutdown() {
            for(auto* peer : remote_peers) {
                if(peer) enet_peer_disconnect_now(peer, 0);
            }
            remote_peers.clear();
            
            if (coordinatorPeer) {
                enet_peer_disconnect_now(coordinatorPeer, 0);
                coordinatorPeer = nullptr;
            }
            
            if (self) {
                enet_host_destroy(self);
                self = nullptr;
            }
            
            initialized = false;
        }
    
        inline bool Client::connect_to_coordinator() {
            if (!initialized) {
                std::cerr << "Client not initialized" << std::endl;
                return false;
            }
    
            if(std::regex_match(coordIp, std::regex("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$"))) {
                // Valid IP format
            } else if(std::regex_match(coordIp, std::regex("^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$"))) {
                struct hostent *he = gethostbyname(coordIp.c_str());
                if (!he) {
                    std::cerr << "Failed to resolve hostname" << std::endl;
                    return false;
                }
                coordIp = inet_ntoa((*((struct in_addr *) he->h_addr_list[0])));
            } else {
                std::cerr << "Invalid IP/domain format" << std::endl;
                return false;
            }
    
            ENetAddress serverAddress;
            if (enet_address_set_host(&serverAddress, coordIp.c_str()) < 0) {
                std::cerr << "Failed to set host address" << std::endl;
                return false;
            }
            serverAddress.port = DEFAULT_PORT;
    
            coordinatorPeer = enet_host_connect(self, &serverAddress, 2, 0);
            if (!coordinatorPeer) {
                std::cerr << "Failed to create coordinator peer" << std::endl;
                return false;
            }
    
            ENetEvent event;
            if (enet_host_service(self, &event, CLIENT_TIMEOUT) > 0 && 
                event.type == ENET_EVENT_TYPE_CONNECT) {
                return true;
            }
    
            if (coordinatorPeer) {
                enet_peer_reset(coordinatorPeer);
                coordinatorPeer = nullptr;
            }
            return false;
        }
    
        inline void Client::update() {
            if (!initialized) return;
    
            ENetEvent event;
            while (enet_host_service(self, &event, CLIENT_TIMEOUT) > 0) {
                switch (event.type) {
                    case ENET_EVENT_TYPE_CONNECT:
                        handleConnect(event);
                        break;
                    case ENET_EVENT_TYPE_RECEIVE:
                        handleMessage(event, event.packet);
                        enet_packet_destroy(event.packet);
                        break;
                    case ENET_EVENT_TYPE_DISCONNECT:
                        handleDisconnect(event);
                        break;
                    case ENET_EVENT_TYPE_NONE:
                        std::cerr << "wuh oh";
                        break;
                    default:
                        std::cerr << "Unknown or invalid event type occurred." << std::endl;
                }
            }
        }
    
        inline bool Client::host_session() {
            if (!coordinatorPeer) return false;
            if(isHost) return true;
            
            NetworkMessage msg;
            msg.type = MessageType::HOST_SESSION;
            ENetPacket* packet = enet_packet_create(&msg, sizeof(NetworkMessage), 
                                                  ENET_PACKET_FLAG_RELIABLE);
            return enet_peer_send(coordinatorPeer, 0, packet) == 0;
        }
    
        inline bool Client::join_session(uint32_t sessionId) {
            if (!coordinatorPeer || isHost) return false;
            
            NetworkMessage msg;
            msg.type = MessageType::JOIN_SESSION;
            msg.data.resize(sizeof(uint32_t));
            memcpy(msg.data.data(), &sessionId, sizeof(uint32_t));
            
            ENetPacket* packet = enet_packet_create(msg.data.data(), msg.data.size(), 
                                                  ENET_PACKET_FLAG_RELIABLE);
            return enet_peer_send(coordinatorPeer, 0, packet) == 0;
        }
    
        inline bool Client::leave_session() {
            NetworkMessage msg;
            msg.type = MessageType::LEAVE_SESSION;
            
            if(isHost) {
                for(auto* peer : remote_peers) {
                    if(peer) {
                        ENetPacket* packet = enet_packet_create(&msg, sizeof(NetworkMessage),
                                                              ENET_PACKET_FLAG_RELIABLE);
                        enet_peer_send(peer, 1, packet);
                    }
                }
                remote_peers.clear();
                isHost = false;
            } else if(!remote_peers.empty()) {
                ENetPacket* packet = enet_packet_create(&msg, sizeof(NetworkMessage),
                                                      ENET_PACKET_FLAG_RELIABLE);
                enet_peer_send(remote_peers[0], 1, packet);
                remote_peers.clear();
            }
            
            sessionId = 0;
            return true;
        }
    
        inline void Client::disconnect() {
            if (coordinatorPeer) {
                enet_peer_disconnect(coordinatorPeer, 0);
                coordinatorPeer = nullptr;
            }
            if (self) {
                enet_host_destroy(self);
                self = nullptr;
            }
        }
    
        inline const std::vector<ENetPeer*>& Client::get_remote_peers() const { 
            return remote_peers; 
        }
        
        inline bool Client::is_session_host() const { 
            return isHost; 
        }
        
        inline bool Client::is_connected() const { 
            return coordinatorPeer != nullptr; 
        }
        
        inline uint32_t Client::get_sessionId() const { 
            return sessionId; 
        }
    
        inline void Client::send_to_all_peers(const void* data, size_t dataLength, bool reliable) {
            uint32_t flags = reliable ? ENET_PACKET_FLAG_RELIABLE : 0;
            for(auto* peer : remote_peers) {
                if(peer) {
                    ENetPacket* packet = enet_packet_create(data, dataLength, flags);
                    enet_peer_send(peer, 1, packet);
                }
            }
        }
    
        inline void Client::send_to_host(const void* data, size_t dataLength, bool reliable) {
            if(!remote_peers.empty()) {
                uint32_t flags = reliable ? ENET_PACKET_FLAG_RELIABLE : 0;
                ENetPacket* packet = enet_packet_create(data, dataLength, flags);
                enet_peer_send(remote_peers[0], 1, packet);
            }
        }
    
        inline std::string Client::randomId(size_t length) {
            using std::chrono::high_resolution_clock;
            static thread_local std::mt19937 rng(
                static_cast<unsigned int>(high_resolution_clock::now().time_since_epoch().count()));
            static const std::string characters(
                "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
            std::string id(length, '0');
            std::uniform_int_distribution<int> uniform(0, int(characters.size() - 1));
            std::generate(id.begin(), id.end(), [&]() { return characters.at(uniform(rng)); });
            return id;
        }
    
        inline void Client::handleConnect(ENetEvent& event) {
            if (event.peer == coordinatorPeer) {
                std::cout << "Client: Connection event with coordinator peer confirmed/re-established." << std::endl;
            } else {
                char ipStr[40];
                enet_address_get_host_ip(&event.peer->address, ipStr, sizeof(ipStr));
                std::cout << "Client: Received ENET_EVENT_TYPE_CONNECT from peer: " 
                         << ipStr << ":" << event.peer->address.port << std::endl;
                
                if (std::find(remote_peers.begin(), remote_peers.end(), event.peer) == remote_peers.end()) {
                    std::cout << "Client: Adding peer " << ipStr << ":" 
                             << event.peer->address.port << " to remote_peers." << std::endl;
                    if (!isHost && remote_peers.empty()) {
                        std::cout << "Client: Assuming this is the host connection." << std::endl;
                    }
                    remote_peers.push_back(event.peer);
                }
            }
        }
    
        inline void Client::handleDisconnect(ENetEvent& event) {
            if(isHost) {
                auto it = std::find(remote_peers.begin(), remote_peers.end(), event.peer);
                if(it != remote_peers.end()) {
                    remote_peers.erase(it);
                    
                    NetworkMessage msg;
                    msg.type = MessageType::DISCONNECT;
                    msg.data.resize(sizeof(ENetAddress));
                    memcpy(msg.data.data(), &event.peer->address, sizeof(ENetAddress));
                    
                    for(auto* peer : remote_peers) {
                        if(peer) {
                            ENetPacket* packet = enet_packet_create(
                                msg.data.data(),
                                msg.data.size(),
                                ENET_PACKET_FLAG_RELIABLE
                            );
                            enet_peer_send(peer, 1, packet);
                        }
                    }
                }
            } else {
                if(!remote_peers.empty() && event.peer == remote_peers[0]) {
                    remote_peers.clear();
                    sessionId = 0;
                }
            }
        }
    
        inline void Client::handleMessage(ENetEvent& event, ENetPacket* packet) {
            MessageReader reader(packet);
            
            if(event.channelID == 0) { // Reserved coordinator channel
                CoordMsgType msgType = reader.read<CoordMsgType>();
                switch(msgType) {
                    case CoordMsgType::AssignHost: {
                        isHost = true;
                        sessionId = reader.read<uint32_t>();
                        std::cout << "Assigned as host of session " << sessionId << std::endl;
                        break;
                    }
                    case CoordMsgType::GetHost: {
                        uint32_t hostAddr = reader.read<uint32_t>();
                        uint16_t hostPort = reader.read<uint16_t>();
                        
                        ENetAddress addr;
                        addr.host = hostAddr;
                        addr.port = hostPort;
                        
                        std::cout << "Connecting to host at " << hostAddr << ":" << hostPort << std::endl;
                        
                        ENetPeer* hostPeer = enet_host_connect(self, &addr, 2, 0);
                        if (!hostPeer) {
                            std::cerr << "Failed to create connection to host" << std::endl;
                        }
                        break;
                    }
                    case CoordMsgType::PeerList: {
                        if(isHost) {
                            unsigned int size = reader.read<unsigned int>();
                            std::cout << "Host received peer list with " << size << " peers" << std::endl;
                            for(unsigned int i = 0; i < size; i++) {
                                uint32_t peerHost = reader.read<uint32_t>();
                                uint16_t peerPort = reader.read<uint16_t>();
                                
                                ENetAddress addr;
                                addr.host = peerHost;
                                addr.port = peerPort;
                                
                                std::cout << "Host connecting to peer at " << peerHost << ":" << peerPort << std::endl;
                                ENetPeer* newPeer = enet_host_connect(self, &addr, 2, 0);
                                if(!newPeer) {
                                    std::cerr << "Failed to create connection to peer" << std::endl;
                                }
                            }
                        }
                        break;
                    }
                    // TODO more cases
                }
            } else { // Game data channel
                if (packet->dataLength < sizeof(uint32_t) * 2) return;
                
                uint32_t type_id;
                memcpy(&type_id, packet->data, sizeof(uint32_t));
                
                auto handler = data_handlers.find(type_id);
                if (handler != data_handlers.end()) {
                    std::cout << "Handling game data of type " << type_id << std::endl;
                    handler->second(
                        packet->data + sizeof(uint32_t) * 2,
                        packet->dataLength - sizeof(uint32_t) * 2
                    );
                }
            }
        }
    
        inline void Client::handle_sync_packet(const uint8_t* data, size_t size) {
            if (size < sizeof(SyncPacket)) return;
            
            auto* packet = reinterpret_cast<const SyncPacket*>(data);
            auto handler = data_handlers.find(packet->dataType);
            
            if (handler != data_handlers.end()) {
                handler->second(
                    data + sizeof(SyncPacket),
                    size - sizeof(SyncPacket)
                );
            }
        }
    
} // namespace tornado
    
#endif // tornadoroll    

// MIT License

// Copyright (c) 2025 Thomas Darnell

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
