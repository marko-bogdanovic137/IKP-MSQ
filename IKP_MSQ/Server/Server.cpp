#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "../IKP_MSQ/pch.h"
#include "server.h"
#include <iostream>
#include <chrono>

#define SERVER1_IP "127.0.0.1"
#define SERVER1_PORT 8080

#define SERVER2_IP "127.0.0.1"
#define SERVER2_PORT 8082

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
    char buffer[1024];

    sockaddr_in addr;
    int addrLen = sizeof(addr);
    getpeername(clientSocket, (sockaddr*)&addr, &addrLen);
    std::string clientIp = inet_ntoa(addr.sin_addr);

    while (running) {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) break;

        buffer[bytesReceived] = '\0';
        std::string message(buffer);

        std::string messageWithIp = clientIp + ": " + message;
        std::cout << "[CLIENT] " << messageWithIp << std::endl;

        clientQueue.enqueue(messageWithIp);   // klijenti
        serverQueue.enqueue(messageWithIp);   // server2 → server1
        SendToQueue("OtherServerQueue", messageWithIp);
    }

    closesocket(clientSocket);
}

void Server::forwardToClient(SOCKET clientSocket) {
    while (running) {
        while (!clientQueue.isEmpty()) {
            std::string message = clientQueue.dequeue();
            int bytesSent = send(clientSocket, message.c_str(), static_cast<int>(message.size()), 0);
            if (bytesSent == SOCKET_ERROR) {
                std::cerr << "Error sending message to client: " << WSAGetLastError() << std::endl;
                return;
            }
            std::cout << "Forwarded message to client: " << message << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// --------------------- SERVER-TO-SERVER SOCKET -----------------------
void Server::handleServerConnection() {
    std::cout << "[Server2] Pokrece konekciju ka drugom serveru..." << std::endl;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    std::string otherServerIp = (port == SERVER2_PORT) ? SERVER1_IP : SERVER2_IP;
    int otherServerPort = (port == SERVER2_PORT) ? SERVER1_PORT : SERVER2_PORT;

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) { std::cerr << "Failed to create socket." << std::endl; WSACleanup(); return; }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(otherServerPort);
    inet_pton(AF_INET, otherServerIp.c_str(), &serverAddr.sin_addr);

    std::cout << "[Server2] Attempting connection to " << otherServerIp << ":" << otherServerPort << "..." << std::endl;

    while (running) {
        if (connect(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "[Server2] Connect failed, retrying in 1s: " << WSAGetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        std::cout << "[Server2] Connected to other server!" << std::endl;
        break;
    }

    threadPool.enqueue([this, serverSocket]() { receiveFromServer(serverSocket); });
    threadPool.enqueue([this, serverSocket]() { forwardToServer(serverSocket); });
}

void Server::receiveFromServer(SOCKET serverSocket) {
    char buffer[1024];

    while (running) {
        int bytesReceived = recv(serverSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) break;

        buffer[bytesReceived] = '\0';
        std::string message(buffer);
        std::cout << "[SERVER] Received message: " << message << std::endl;

        clientQueue.enqueue(message); // prosledjujemo klijentima
    }

    closesocket(serverSocket);
}

void Server::forwardToServer(SOCKET serverSocket) {
    while (running) {
        while (!serverQueue.isEmpty()) {
            std::string message = serverQueue.dequeue();
            int bytesSent = send(serverSocket, message.c_str(), static_cast<int>(message.size()), 0);
            if (bytesSent == SOCKET_ERROR) {
                std::cerr << "[SERVER] Error sending to other server: " << WSAGetLastError() << std::endl;
                return;
            }
            std::cout << "[SERVER] Forwarded message to other server: " << message << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
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
    bool connectToOther = false;

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
