#include "pch.h"
#include "Server.h"
#include <iostream>

Server::Server(const std::string& serverAddress, int port, bool isClient, size_t threadPoolSize)
    : serverAddress(serverAddress),
    port(port),
    running(false),
    threadPool(threadPoolSize),
    isClient(isClient) {
}

Server::~Server() {
    stop();
}

void Server::SendToQueue(const std::string& queueName, const std::string& message) {
    messageQueueService.SendMessage(queueName, message.c_str(), static_cast<int>(message.size()));
}

void Server::start() {
    running = true;

    if (isClient) {
        threadPool.enqueue([this]() { handleServerConnection(); });
    }
    else {
        threadPool.enqueue([this]() { handleClientConnection(); });
    }
}

void Server::stop() {
    running = false;
}

void Server::handleClientConnection() {
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed." << std::endl;
        WSACleanup();
        return;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    std::cout << "Server listening on port " << port << "..." << std::endl;

    clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Accept failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    std::cout << "Client connected." << std::endl;

    threadPool.enqueue([this, clientSocket]() { forwardToClient(clientSocket); });
    threadPool.enqueue([this, clientSocket]() { receiveFromOtherServer(clientSocket); });

    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    closesocket(clientSocket);
    closesocket(serverSocket);
    WSACleanup();
}

void Server::handleServerConnection() {
    // Placeholder – ovde ide logika za konekciju na drugi server
    std::cout << "Connecting to other server..." << std::endl;
}

void Server::receiveFromOtherServer(SOCKET otherServerSocket) {
    char buffer[1024];
    while (running) {
        int bytesReceived = recv(otherServerSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            std::cerr << "Connection closed or error." << std::endl;
            break;
        }
        buffer[bytesReceived] = '\0';

        std::string message(buffer);
        SendToQueue("incoming", message);
    }
}

void Server::forwardToClient(SOCKET clientSocket) {
    auto queue = messageQueueService.GetQueue("incoming");
    if (!queue) return;

    while (running) {
        std::string message = queue->dequeue();
        if (send(clientSocket, message.c_str(), static_cast<int>(message.size()), 0) == SOCKET_ERROR) {
            std::cerr << "Failed to forward message to client." << std::endl;
        }
        else {
            messageQueueService.ConfirmMessageDelivered("incoming", message);
        }
    }
}
