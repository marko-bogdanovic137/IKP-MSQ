#include "../IKP_MSQ/pch.h"
#include "server.h"
#include <iostream>

#define SERVER1_IP "127.0.0.1"
#define SERVER1_PORT 8080

#define SERVER2_IP "127.0.0.1"
#define SERVER2_PORT 8082

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

    threadPool.enqueue([this, clientSocket]() { receiveFromClient(clientSocket); });
    threadPool.enqueue([this, clientSocket]() { forwardToClient(clientSocket); });

    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    closesocket(clientSocket);
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
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            std::cerr << "Client disconnected or error." << std::endl;
            break;
        }
        buffer[bytesReceived] = '\0';
        std::string message(buffer);

        std::string messageWithIp = clientIp + ": " + message;
        std::cout << "[CLIENT] " << messageWithIp << std::endl;
     
        sendingQueue.enqueue(messageWithIp);
        
        SendToQueue("OtherServerQueue", messageWithIp);
    }
}



void Server::handleServerConnection() {
    // Placeholder – ovde ide logika za konekciju na drugi server
    std::cout << "Connecting to other server..." << std::endl;
}

void Server::forwardToClient(SOCKET clientSocket) {
    while (running) {
        while (!sendingQueue.isEmpty()) {
            std::string message = sendingQueue.dequeue();
            int bytesSent = send(clientSocket, message.c_str(), message.size(), 0);
            if (bytesSent == SOCKET_ERROR) {
                std::cerr << "Error sending message to client: " << WSAGetLastError() << std::endl;
                return;
            }
            std::cout << "Forwarded message to client: " << message << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main() {
    std::cout << "Odaberite server: 1 ili 2? ";
    int choice;
    std::cin >> choice;
    std::cin.ignore(); // uklanja \n sa ulaza

    std::string ip;
    int port;
    bool isClient = false; 

    if (choice == 1) {
        ip = SERVER1_IP;
        port = SERVER1_PORT;
    }
    else if (choice == 2) {
        ip = SERVER2_IP;
        port = SERVER2_PORT;
        isClient = true; 
    }
    else {
        std::cerr << "Nepoznata opcija." << std::endl;
        return 1;
    }

    try {
        Server server(ip, port, isClient);
        server.start();

        std::cout << "Server radi. Ukucajte 'exit' da zaustavite server." << std::endl;
        std::string command;
        while (true) {
            std::getline(std::cin, command);
            if (command == "exit") {
                server.stop();
                break;
            }
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Greška: " << ex.what() << std::endl;
    }

    std::cout << "Server je zaustavljen." << std::endl;
    return 0;
}
