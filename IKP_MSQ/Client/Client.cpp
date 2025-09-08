#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include "../IKP_MSQ/ThreadPool.h"
#include "../IKP_MSQ/ConcreteMessageQueueService.h"

#pragma comment(lib, "ws2_32.lib")

#define SERVER1_IP   "127.0.0.1"
#define SERVER1_PORT 8080

#define SERVER2_IP   "127.0.0.1"
#define SERVER2_PORT 8082

#define BUFFER_SIZE 1024
#define FRIEND "Soko"

std::atomic<bool> running(true);
ConcreteMessageQueueService messageQueueService;

void receiveMessages(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    while (running) {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) {
            std::cerr << "\nDisconnected from server." << std::endl;
            running = false;
            break;
        }
        buffer[bytesReceived] = '\0';

        std::string msg(buffer);
        messageQueueService.SendMessage("incoming", msg.c_str(), static_cast<int>(msg.size()));

        std::cout << "\n[" << FRIEND << "]: " << msg << std::endl;
        std::cout << "(type 'exit' to quit) [Me]: ";
    }
}

void sendMessages(SOCKET clientSocket, const std::string& myIp) {
    std::string message;
    const size_t MAX_MESSAGE_LENGTH = 512;

    while (running) {
        std::cout << "\n(type 'exit' to quit) [Me]: ";
        std::getline(std::cin, message);

        if (!running) break;

        if (message == "exit") {
            send(clientSocket, message.c_str(), static_cast<int>(message.size()), 0);
            running = false;
            break;
        }

        if (message.length() > MAX_MESSAGE_LENGTH) {
            std::cerr << "Message too long (max 512 chars)." << std::endl;
            continue;
        }

        std::string messageWithIp = myIp + ": " + message;
        int bytesSent = send(clientSocket, messageWithIp.c_str(), static_cast<int>(messageWithIp.size()), 0);
        if (bytesSent == SOCKET_ERROR) {
            std::cerr << "Failed to send message. Error: " << WSAGetLastError() << std::endl;
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main() {
    int clientNumber;
    std::cout << "Unesi broj klijenta (1 ili 2): ";
    std::cin >> clientNumber;
    std::cin.ignore();

    std::string serverIp = (clientNumber == 1) ? SERVER1_IP : SERVER2_IP;
    int serverPort = (clientNumber == 1) ? SERVER1_PORT : SERVER2_PORT;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection to server failed." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Client " << clientNumber << " connected to server " << serverIp << ":" << serverPort << std::endl;

    // Dohvat lokalne IP adrese
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    hostent* localHost = gethostbyname(hostname);
    std::string myIp = inet_ntoa(*(in_addr*)localHost->h_addr_list[0]);

    ThreadPool threadPool(2);
    threadPool.enqueue([clientSocket]() { receiveMessages(clientSocket); });
    threadPool.enqueue([clientSocket, myIp]() { sendMessages(clientSocket, myIp); });

    // Glavna petlja čeka da se završi rad
    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    closesocket(clientSocket);
    WSACleanup();

    std::cout << "Client " << clientNumber << " has stopped." << std::endl;
    return 0;
}
