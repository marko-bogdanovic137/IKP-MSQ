#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../IKP_MSQ/pch.h"
#include "server.h"
#include <iostream>
#include <chrono>

#define SERVER1_IP "127.0.0.1"
#define SERVER1_PORT 8080

#define SERVER2_IP "127.0.0.1"
#define SERVER2_PORT 8082
///////////////////////HELPER FUNKCIJE
// --- framing + helpers (paste near top of server.cpp and client.cpp) ---
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
    // recvAll into mutable buffer
    if (!recvAll(sock, &out[0], (int)len)) return false;
    return true;
}
//////////

Server::Server(const std::string& serverAddress, int port, bool connectToOtherServer, size_t threadPoolSize)
    : serverAddress(serverAddress),
    port(port),
    running(false),
    threadPool(threadPoolSize),
    connectToOtherServer(connectToOtherServer) {
}

Server::~Server() {
    stop();
}

void Server::SendToQueue(const std::string& queueName, const std::string& message) {
    messageQueueService.SendMessage(queueName, message.c_str(), static_cast<int>(message.size()));
}

void Server::start() {
    running = true;
    // Pokrecemo klijentski server
    threadPool.enqueue([this]() { handleClientConnection(); });

    // Ako treba da se povezemo na drugi server
    if (connectToOtherServer) StartServerConnection();
}

void Server::stop() {
    running = false;
}

// --------------------- KLJIENTSKI SOCKET -----------------------
void Server::handleClientConnection() {
    WSADATA wsaData;
    SOCKET serverSocket;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) { WSACleanup(); return; }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(serverSocket); WSACleanup(); return;
    }

    std::cout << "Server bound to port " << port << std::endl;

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(serverSocket); WSACleanup(); return;
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;

    while (running) {
        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) continue;

        std::cout << "Client connected from " << inet_ntoa(clientAddr.sin_addr) << std::endl;

        threadPool.enqueue([this, clientSocket]() { receiveFromClient(clientSocket); });
        threadPool.enqueue([this, clientSocket]() { forwardToClient(clientSocket); });
    }

    closesocket(serverSocket);
    WSACleanup();
}

void Server::receiveFromClient(SOCKET clientSocket) {
    char buf[1024];
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

            // Ako klijent slučajno pošalje paket koji već počinje sa "CLIENT|", odbacimo ponovno tagovanje.
            if (msg.rfind("CLIENT|", 0) == 0 || msg.rfind("SYSTEM|", 0) == 0) {
                // Ako je već server-tagovana poruka (ne bi trebalo), samo enqueue payload za lokalne klijente.
                // Ovde rastavimo ako je CLIENT|ip|payload
                if (msg.rfind("CLIENT|", 0) == 0) {
                    size_t sep = msg.find('|', 7);
                    if (sep != std::string::npos) {
                        std::string payload = msg.substr(sep + 1);
                        sendingQueue.enqueue(payload);
                        std::cout << "[DEBUG] receiveFromClient: incoming already-tagged CLIENT, enqueued payload to sendingQueue." << std::endl;
                    }
                    else {
                        // Malformat: enqueue sirovo
                        sendingQueue.enqueue(msg);
                    }
                }
                else {
                    // SYSTEM or other: treat as local payload
                    sendingQueue.enqueue(msg);
                }
                continue;
            }

            // Ovo je poruka od lokalnog klijenta: tagujemo za server-server i enqueue-ujemo
            std::string packet = "CLIENT|" + clientIp + "|" + msg;

            // ENQUEUE: lokalno (da bi lokalni client mogao dobiti i svoju poruku ako je potrebno)
            sendingQueue.enqueue(clientIp + ": " + msg);
            std::cout << "[DEBUG] receiveFromClient: enqueued to sendingQueue (local)." << std::endl;

            // ENQUEUE: za slanje drugom serveru (samo jednom)
            serverQueue.enqueue(packet);
            std::cout << "[DEBUG] receiveFromClient: enqueued to serverQueue (for other server): " << packet << std::endl;
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





// --------------------- SERVER-TO-SERVER SOCKET -----------------------
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

            // Ako je packet SERVER->SERVER formiran od strane drugog servera kao "CLIENT|<ip>|<payload>"
            const std::string clientPrefix = "CLIENT|";
            if (packet.rfind(clientPrefix, 0) == 0) {
                // Ne smemo ovaj packet ponovno staviti u serverQueue (pravimo loop).
                // Treba izvuci payload i poslati lokalnim klijentima.
                size_t secondSep = packet.find('|', clientPrefix.size());
                if (secondSep != std::string::npos) {
                    std::string payload = packet.substr(secondSep + 1);
                    sendingQueue.enqueue(payload);
                    std::cout << "[DEBUG] receiveFromServer: enqueued payload to sendingQueue (from other server): " << payload << std::endl;
                }
                else {
                    // malformed - enqueue raw to local queue
                    sendingQueue.enqueue(packet);
                    std::cout << "[DEBUG] receiveFromServer: malformed CLIENT packet, enqueued raw." << std::endl;
                }
            }
            else {
                // Ne prepoznajemo format -> log + ignore ili enqueue localno
                std::cout << "[DEBUG] receiveFromServer: unknown packet type, enqueuing local: " << packet << std::endl;
                sendingQueue.enqueue(packet);
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
    try {
        while (running) {
            std::string packet;
            if (!serverQueue.tryDequeue(packet)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            // Pre slanja proverimo da packet nije prazan i da ima CLIENT| prefiks
            if (packet.empty()) continue;

            // Debug
            std::cout << "[DEBUG] forwardToServer: dequeued -> " << packet << std::endl;

            if (!sendMessage(serverSocket, packet)) {
                std::cerr << "[DEBUG] forwardToServer: sendMessage failed. Other server probably disconnected." << std::endl;
                break;
            }

            std::cout << "[DEBUG][Thread " << GetCurrentThreadId() << "] Forwarded message to OTHER SERVER: " << packet << std::endl;
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






// --------------------- POKRETANJE SERVERA -----------------------
void Server::StartServerConnection() {
    threadPool.enqueue([this]() { handleServerConnection(); });
}

int main() {
    std::cout << "Odaberite server: 1 ili 2? ";
    int choice;
    std::cin >> choice; std::cin.ignore();

    std::string ip;
    int port;
    bool connectToOther = true;

    if (choice == 1) { ip = SERVER1_IP; port = SERVER1_PORT; }
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
