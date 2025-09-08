#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include "../IKP_MSQ/ThreadPool.h"
#include "../IKP_MSQ/ConcreteMessageQueueService.h"

#pragma comment(lib, "ws2_32.lib") // Linkovanje Winsock biblioteke

#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define FRIEND "Soko"

std::string globalShutdownFlag = "running";
ConcreteMessageQueueService messageQueueService;

void receiveMessages(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    while (globalShutdownFlag == "running") {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            std::cerr << "\nFailed to receive message from server." << std::endl;
            break;
        }
        buffer[bytesReceived] = '\0';

        std::string msg(buffer);
        messageQueueService.SendMessage("incoming", msg.c_str(), static_cast<int>(msg.size()));

        std::cout << "\n[" << FRIEND << "]: " << msg << std::endl;
        std::cout << "(type 'exit' to quit) [Me]: ";
    }
}

// sendMessage funkcija u Clientu
void sendMessages(SOCKET clientSocket, const std::string& myIp) {
    std::string message;
    while (globalShutdownFlag == "running") {
        std::cout << "\n(type 'exit' to quit) [Me]: ";
        std::getline(std::cin, message);

        if (message == "exit") {
            send(clientSocket, message.c_str(), message.size(), 0);
            globalShutdownFlag = "shutdown";
            break;
        }

        // Dodajemo IP u poruku
        std::string messageWithIp = myIp + ": " + message;

        if (send(clientSocket, messageWithIp.c_str(), messageWithIp.size(), 0) == SOCKET_ERROR) {
            std::cerr << "\nFailed to send message to server. " << std::endl;
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}



#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include "../IKP_MSQ/ThreadPool.h"
#include "../IKP_MSQ/ConcreteMessageQueueService.h"

#pragma comment(lib, "ws2_32.lib")

#define BUFFER_SIZE 1024
#define FRIEND "Soko"

std::string globalShutdownFlag = "running";
ConcreteMessageQueueService messageQueueService;

void receiveMessages(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    while (globalShutdownFlag == "running") {
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            std::cerr << "\nConnection closed by server or error." << std::endl;
            globalShutdownFlag = "shutdown";
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
    while (globalShutdownFlag == "running") {
        std::cout << "\n(type 'exit' to quit) [Me]: ";
        std::getline(std::cin, message);
        if (message == "exit") {
            send(clientSocket, message.c_str(), message.size(), 0);
            globalShutdownFlag = "shutdown";
            break;
        }

        std::string messageWithIp = myIp + ": " + message;
        if (send(clientSocket, messageWithIp.c_str(), messageWithIp.size(), 0) == SOCKET_ERROR) {
            std::cerr << "\nFailed to send message to server." << std::endl;
            continue;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

int main(int argc, char* argv[]) {
    int clientNumber = 1;
    if (argc > 1) {
        clientNumber = std::stoi(argv[1]);
    }

    std::string serverIp = (clientNumber == 1) ? "192.168.1.12" : "192.168.1.7";
    int serverPort = (clientNumber == 1) ? 8080 : 8082;

    WSADATA wsaData;
    SOCKET clientSocket;
    sockaddr_in serverAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        WSACleanup();
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection to server failed" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Client " << clientNumber << " connected to server " << serverIp << ":" << serverPort << std::endl;

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    hostent* localHost = gethostbyname(hostname);
    std::string myIp = inet_ntoa(*(in_addr*)localHost->h_addr_list[0]);

    ThreadPool threadPool(2);
    threadPool.enqueue([clientSocket]() { receiveMessages(clientSocket); });
    threadPool.enqueue([clientSocket, myIp]() { sendMessages(clientSocket, myIp); });

    while (globalShutdownFlag == "running") {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    closesocket(clientSocket);
    WSACleanup();

    std::cout << "Client has stopped." << std::endl;
    return 0;
}

