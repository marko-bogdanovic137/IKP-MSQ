#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../IKP_MSQ/pch.h"
#include "server.h"
#include <iostream>
#include <chrono>
#include <sstream>
#include <cstring>

#define SERVER1_IP "127.0.0.1"
#define SERVER1_PORT 8080

#define SERVER2_IP "127.0.0.1"
#define SERVER2_PORT 8082

// framing + helpers (length-prefixed messages)
#include <cstdint>

// send all bytes
static bool sendAll(SOCKET sock, const char* data, int totalLen) {
    int sent = 0;
    while (sent < totalLen) {
        int s = send(sock, data + sent, totalLen - sent, 0);
        if (s == SOCKET_ERROR) return false;
        if (s == 0) return false;
        sent += s;
    }
    return true;
}

// recv exactly len bytes, return false on error/peer close
static bool recvAll(SOCKET sock, char* buffer, int len) {
    int got = 0;
    while (got < len) {
        int r = recv(sock, buffer + got, len - got, 0);
        if (r == 0) return false; // graceful close
        if (r == SOCKET_ERROR) return false;
        got += r;
    }
    return true;
}

// send length-prefixed message (4-byte network-order length + payload)
static bool sendMessage(SOCKET sock, const std::string& msg) {
    uint32_t n = (uint32_t)msg.size();
    uint32_t net = htonl(n);
    if (!sendAll(sock, reinterpret_cast<const char*>(&net), 4)) return false;
    if (n == 0) return true;
    return sendAll(sock, msg.data(), (int)n);
}

// receive length-prefixed message (returns false on error/close)
static bool recvMessage(SOCKET sock, std::string& out) {
    uint32_t netlen = 0;
    if (!recvAll(sock, reinterpret_cast<char*>(&netlen), 4)) return false;
    uint32_t len = ntohl(netlen);
    if (len == 0) { out.clear(); return true; }
    out.resize(len);
    if (!recvAll(sock, &out[0], (int)len)) return false;
    return true;
}

// ------------------- Server implementation -------------------

Server::Server(const std::string& serverAddress, int port, bool connectToOtherServer, size_t threadPoolSize)
    : serverAddress(serverAddress),
    port(port),
    running(false),
    threadPool(threadPoolSize),
    connectToOtherServer(connectToOtherServer),
    msgCounter(0) {
}

Server::~Server() {
    stop();
}

void Server::SendToQueue(const std::string& queueName, const std::string& message) {
    messageQueueService.SendMessage(queueName, message.c_str(), static_cast<int>(message.size()));
}

void Server::start() {
    running = true;
    // Pokrecemo klijentski server (accept loop)
    threadPool.enqueue([this]() { handleClientConnection(); });

    // Ako treba da se povezemo na drugi server (outbound)
    if (connectToOtherServer) StartServerConnection();
}

void Server::stop() {
    running = false;
}

// ------------------- Helpers -------------------

std::string Server::GenerateMessageID() {
    // simple: monotonic counter + timestamp
    unsigned long long counter = ++msgCounter;
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    std::ostringstream oss;
    oss << now << "_" << counter;
    return oss.str();
}

// Classification: check shortly whether accepted socket is "server" (handshake "SERVER|...").
// returns true and fills handshakeOut if it is server; returns false otherwise.
bool Server::isIncomingServerSocket(SOCKET sock, std::string& handshakeOut) {
    // set a small receive timeout
    int timeoutMs = 200; // 200ms to decide
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

    // Try to peek 4 bytes (length prefix)
    char hdr[4];
    int r = recv(sock, hdr, 4, MSG_PEEK);
    if (r == SOCKET_ERROR) {
        int err = WSAGetLastError();
        // timed out or nothing arrived -> treat as normal client
        if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
            // restore blocking (timeout 0)
            timeoutMs = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
            return false;
        }
        // other error -> treat as client
        timeoutMs = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        return false;
    }
    if (r < 4) {
        // not enough data yet -> treat as client
        timeoutMs = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        return false;
    }

    // parse length
    uint32_t netlen = 0;
    memcpy(&netlen, hdr, 4);
    uint32_t len = ntohl(netlen);
    if (len == 0 || len > 20000) { // sanity
        timeoutMs = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        return false;
    }

    // peek entire message
    std::vector<char> buf(4 + len);
    int r2 = recv(sock, buf.data(), static_cast<int>(buf.size()), MSG_PEEK);
    if (r2 == SOCKET_ERROR || r2 < static_cast<int>(4 + len)) {
        timeoutMs = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        return false;
    }

    std::string payload(buf.data() + 4, len);
    // restore blocking
    timeoutMs = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));

    if (payload.rfind("SERVER|", 0) == 0) {
        handshakeOut = payload;
        // consume the message (actually remove from socket) by reading it normally
        std::string consumed;
        if (!recvMessage(sock, consumed)) {
            return false; // socket error
        }
        return true;
    }

    return false;
}

// --------------------- KLJIENTSKI SOCKET (accept) -----------------------
void Server::handleClientConnection() {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return;
    }

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) { WSACleanup(); return; }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(listenSocket); WSACleanup(); return;
    }

    std::cout << "Server bound to port " << port << std::endl;

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSocket); WSACleanup(); return;
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;

    while (running) {
        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if (!running) break;
            std::cerr << "accept failed: " << err << std::endl;
            continue;
        }

        std::cout << "Client connected from " << inet_ntoa(clientAddr.sin_addr) << std::endl;

        // Try to detect if this accepted socket is actually from the other server (handshake)
        std::string handshake;
        bool isServer = isIncomingServerSocket(clientSocket, handshake);
        if (isServer) {
            std::cout << "[DEBUG] Accepted incoming server connection (handshake=" << handshake << "). Treating as server-socket." << std::endl;
            threadPool.enqueue([this, clientSocket]() { receiveFromServer(clientSocket); });
            threadPool.enqueue([this, clientSocket]() { forwardToServer(clientSocket); });
        }
        else {
            // normal local client
            threadPool.enqueue([this, clientSocket]() { receiveFromClient(clientSocket); });
            threadPool.enqueue([this, clientSocket]() { forwardToClient(clientSocket); });
        }
    }

    closesocket(listenSocket);
    WSACleanup();
}

// --------------------- FROM CLIENT -----------------------
void Server::receiveFromClient(SOCKET clientSocket) {
    sockaddr_in addr{};
    int addrLen = sizeof(addr);
    if (getpeername(clientSocket, (sockaddr*)&addr, &addrLen) != 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }
    char ipbuf[INET_ADDRSTRLEN] = { 0 };
    inet_ntop(AF_INET, &addr.sin_addr, ipbuf, sizeof(ipbuf));
    std::string clientIp = ipbuf;

    try {
        while (running) {
            std::string msg;
            if (!recvMessage(clientSocket, msg)) {
                std::cerr << "[DEBUG] receiveFromClient: client disconnected or error (" << clientIp << ")" << std::endl;
                break;
            }

            std::cout << "[DEBUG][Thread " << GetCurrentThreadId() << "] Received from CLIENT: " << clientIp << ": " << msg << std::endl;

            // If client sent ACK (rare), remove pending (safety)
            if (msg.rfind("ACK|", 0) == 0) {
                std::string ackId = msg.substr(4);
                {
                    std::lock_guard<std::mutex> lk(pendingMutex);
                    pendingAcks.erase(ackId);
                }
                std::cout << "[DEBUG] receiveFromClient: got ACK from client for " << ackId << std::endl;
                continue;
            }

            // If the client accidentally sent a packet that already carries MSGID|CLIENT|..., detect and handle:
            // We check whether first token before '|' looks like a msgId (digits + '_' etc). To be conservative:
            size_t firstSep = msg.find('|');
            bool seemsMsgId = false;
            if (firstSep != std::string::npos) {
                std::string firstToken = msg.substr(0, firstSep);
                // treat as MSGID if contains '_' (our GenerateMessageID uses timestamp_counter)
                if (firstToken.find('_') != std::string::npos) {
                    seemsMsgId = true;
                }
            }
            if (seemsMsgId) {
                // If client sent a server-formatted packet (should not), just enqueue the payload after striping msgId| (to avoid re-sending)
                size_t sep2 = msg.find('|', firstSep + 1);
                if (sep2 != std::string::npos) {
                    std::string rest = msg.substr(sep2 + 1);
                    // push to local sending queue (deliver to local clients)
                    sendingQueue.enqueue(rest);
                    std::cout << "[DEBUG] receiveFromClient: incoming already-server-formatted, enqueued to sendingQueue: " << rest << std::endl;
                }
                else {
                    sendingQueue.enqueue(msg);
                }
                continue;
            }

            // Normal local client message: create MSGID and a server-packet
            std::string msgId = GenerateMessageID();
            std::string packet = msgId + "|CLIENT|" + clientIp + "|" + msg;

            // enqueue to serverQueue for sending to other server
            serverQueue.enqueue(packet);
            std::cout << "[DEBUG] receiveFromClient: enqueued to serverQueue (for other server): " << packet << std::endl;

            // enqueue local delivery (local clients)
            sendingQueue.enqueue(clientIp + ": " + msg);
            std::cout << "[DEBUG] receiveFromClient: enqueued to local sendingQueue: " << clientIp << ": " << msg << std::endl;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "[EXCEPTION] receiveFromClient: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[EXCEPTION] receiveFromClient: unknown" << std::endl;
    }

    closesocket(clientSocket);
    std::cout << "[DEBUG] receiveFromClient ended for " << clientIp << std::endl;
}

void Server::forwardToClient(SOCKET clientSocket) {
    try {
        while (running) {
            std::string message;
            if (!sendingQueue.tryDequeue(message)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            if (!sendMessage(clientSocket, message)) {
                std::cerr << "[DEBUG] forwardToClient: sendMessage failed (client maybe disconnected)." << std::endl;
                break;
            }

            std::cout << "[DEBUG][Thread " << GetCurrentThreadId() << "] Forwarded message to CLIENT: " << message << std::endl;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "[EXCEPTION] forwardToClient: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[EXCEPTION] forwardToClient: unknown" << std::endl;
    }

    closesocket(clientSocket);
    std::cout << "[DEBUG] forwardToClient ended and socket closed." << std::endl;
}

// --------------------- SERVER-TO-SERVER (outbound) -----------------------
void Server::handleServerConnection() {
    std::cout << "[DEBUG] Attempting server-to-server connection..." << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[DEBUG] WSAStartup failed for server-to-server connection." << std::endl;
        return;
    }

    std::string otherServerIp = (port == SERVER2_PORT) ? SERVER1_IP : SERVER2_IP;
    int otherServerPort = (port == SERVER2_PORT) ? SERVER1_PORT : SERVER2_PORT;

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[DEBUG] Failed to create server-to-server socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(otherServerPort);
    inet_pton(AF_INET, otherServerIp.c_str(), &serverAddr.sin_addr);

    while (running) {
        if (connect(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "[DEBUG] Connect failed to " << otherServerIp << ":" << otherServerPort
                << ", retrying: " << WSAGetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        std::cout << "[DEBUG] Connected to other server: " << otherServerIp << ":" << otherServerPort << std::endl;
        break;
    }

    // Send a handshake message to identify ourselves as a server (so acceptor can classify)
    std::string handshake = "SERVER|" + serverAddress;
    if (!sendMessage(serverSocket, handshake)) {
        std::cerr << "[DEBUG] handleServerConnection: failed sending handshake." << std::endl;
    }
    else {
        std::cout << "[DEBUG] handleServerConnection: sent handshake to other server." << std::endl;
    }

    // Primanje poruka sa drugog servera
    threadPool.enqueue([this, serverSocket]() { receiveFromServer(serverSocket); });
    // Slanje poruka drugom serveru
    threadPool.enqueue([this, serverSocket]() { forwardToServer(serverSocket); });
}

void Server::receiveFromServer(SOCKET serverSocket) {
    try {
        while (running) {
            std::string packet;
            if (!recvMessage(serverSocket, packet)) {
                std::cerr << "[DEBUG] receiveFromServer: other server disconnected or error." << std::endl;
                break;
            }

            std::cout << "[DEBUG][Thread " << GetCurrentThreadId() << "] Received from SERVER: " << packet << std::endl;

            // ACK from other server?
            if (packet.rfind("ACK|", 0) == 0) {
                std::string ackId = packet.substr(4);
                {
                    std::lock_guard<std::mutex> lk(pendingMutex);
                    if (pendingAcks.erase(ackId) > 0) {
                        std::cout << "[DEBUG] receiveFromServer: ACK received for " << ackId << std::endl;
                    }
                    else {
                        std::cout << "[DEBUG] receiveFromServer: ACK for unknown id " << ackId << std::endl;
                    }
                }
                continue;
            }

            // Expected packet format: "<MSGID>|CLIENT|<ip>|<payload>"
            size_t firstSep = packet.find('|');
            if (firstSep == std::string::npos) {
                std::cout << "[DEBUG] receiveFromServer: malformed packet (no MSGID), enqueuing raw: " << packet << std::endl;
                sendingQueue.enqueue(packet);
                continue;
            }

            std::string msgId = packet.substr(0, firstSep);
            std::string rest = packet.substr(firstSep + 1);

            const std::string clientPrefix = "CLIENT|";
            if (rest.rfind(clientPrefix, 0) == 0) {
                // rest looks like "CLIENT|<ip>|<payload>"
                size_t secondSep = rest.find('|', clientPrefix.size());
                if (secondSep != std::string::npos) {
                    std::string payload = rest.substr(secondSep + 1);

                    // Enqueue payload for local clients
                    sendingQueue.enqueue(payload);
                    std::cout << "[DEBUG] receiveFromServer: enqueued payload to sendingQueue (from other server): " << payload << std::endl;

                    // Send ACK back to the other server to confirm delivery
                    std::string ackPacket = "ACK|" + msgId;
                    if (!sendMessage(serverSocket, ackPacket)) {
                        std::cerr << "[DEBUG] receiveFromServer: failed to send ACK for " << msgId << std::endl;
                    }
                    else {
                        std::cout << "[DEBUG] receiveFromServer: sent ACK for " << msgId << std::endl;
                    }
                }
                else {
                    sendingQueue.enqueue(rest);
                }
            }
            else if (rest.rfind("SERVER|", 0) == 0) {
                // ignore server-to-server handshake payloads here (shouldn't happen)
                std::cout << "[DEBUG] receiveFromServer: got SERVER-handshake payload: " << rest << std::endl;
            }
            else {
                // unknown type
                std::cout << "[DEBUG] receiveFromServer: unknown packet type, enqueuing local: " << rest << std::endl;
                sendingQueue.enqueue(rest);
            }
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "[EXCEPTION] receiveFromServer: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[EXCEPTION] receiveFromServer: unknown" << std::endl;
    }

    closesocket(serverSocket);
    std::cout << "[DEBUG] receiveFromServer ended." << std::endl;
}

void Server::forwardToServer(SOCKET serverSocket) {
    const int MAX_ATTEMPTS = 3;
    const int ACK_WAIT_MS = 500; // how long to wait between attempts

    try {
        while (running) {
            std::string packet;
            if (!serverQueue.tryDequeue(packet)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            if (packet.empty()) continue;

            // Parse msgId
            size_t sep = packet.find('|');
            if (sep == std::string::npos) {
                std::cerr << "[DEBUG] forwardToServer: packet without MSGID, skipping: " << packet << std::endl;
                continue;
            }
            std::string msgId = packet.substr(0, sep);

            {
                std::lock_guard<std::mutex> lk(pendingMutex);
                pendingAcks[msgId] = 0; // waiting for ACK
            }

            bool delivered = false;
            for (int attempt = 1; attempt <= MAX_ATTEMPTS && running; ++attempt) {
                // send
                if (!sendMessage(serverSocket, packet)) {
                    std::cerr << "[DEBUG] forwardToServer: sendMessage failed on attempt " << attempt << " for " << msgId << std::endl;
                    break; // socket likely dead
                }
                std::cout << "[DEBUG] forwardToServer: sent -> " << packet << " (waiting ACK)" << std::endl;

                // wait ACK_WAIT_MS while periodically checking pendingAcks
                int waited = 0;
                while (waited < ACK_WAIT_MS) {
                    {
                        std::lock_guard<std::mutex> lk(pendingMutex);
                        if (pendingAcks.find(msgId) == pendingAcks.end()) {
                            delivered = true;
                            break;
                        }
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    waited += 50;
                }

                if (delivered) break;

                {
                    std::lock_guard<std::mutex> lk(pendingMutex);
                    pendingAcks[msgId] += 1;
                }
                std::cout << "[DEBUG] forwardToServer: ACK not received for " << msgId << " after attempt " << attempt << std::endl;
            }

            if (!delivered) {
                std::lock_guard<std::mutex> lk(pendingMutex);
                pendingAcks.erase(msgId); // give up for now
                std::cerr << "[DEBUG] forwardToServer: giving up on " << msgId << std::endl;
            }
            else {
                std::cout << "[DEBUG] forwardToServer: confirmed delivery for " << msgId << std::endl;
            }
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "[EXCEPTION] forwardToServer: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[EXCEPTION] forwardToServer: unknown" << std::endl;
    }

    closesocket(serverSocket);
    std::cout << "[DEBUG] forwardToServer ended and socket closed." << std::endl;
}

// --------------------- START SERVER-TO-SERVER (kickoff) -----------------------
void Server::StartServerConnection() {
    threadPool.enqueue([this]() { handleServerConnection(); });
}

// --------------------- main -----------------------
int main() {
    std::cout << "Odaberite server: 1 ili 2? ";
    int choice;
    std::cin >> choice; std::cin.ignore();

    std::string ip;
    int port;
    bool connectToOther = false;

    if (choice == 1) { ip = SERVER1_IP; port = SERVER1_PORT; connectToOther = false; }
    else if (choice == 2) { ip = SERVER2_IP; port = SERVER2_PORT; connectToOther = true; }
    else { std::cerr << "Nepoznata opcija." << std::endl; return 1; }

    Server server(ip, port, connectToOther);
    server.start();

    std::cout << "Server radi. Ukucajte 'exit' da zaustavite server." << std::endl;
    std::string command;
    while (true) {
        std::getline(std::cin, command);
        if (command == "exit") { server.stop(); break; }
    }

    std::cout << "Server je zaustavljen." << std::endl;
    return 0;
}
