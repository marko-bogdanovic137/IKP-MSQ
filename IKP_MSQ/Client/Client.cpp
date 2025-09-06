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

void sendMessages(SOCKET clientSocket) {
    std::string message;
    auto outgoingQueue = messageQueueService.GetQueue("outgoing");
    if (!outgoingQueue) {
        messageQueueService.CreateQueue("outgoing");
        outgoingQueue = messageQueueService.GetQueue("outgoing");
    }

    while (globalShutdownFlag == "running") {
        std::cout << "\n(type 'exit' to quit) [Me]: ";
        std::getline(std::cin, message);

        if (message == "exit") {
            send(clientSocket, message.c_str(), static_cast<int>(message.size()), 0);
            globalShutdownFlag = "shutdown";
            break;
        }

        outgoingQueue->enqueue(message);

        std::string msgToSend = outgoingQueue->dequeue();
        if (send(clientSocket, msgToSend.c_str(), static_cast<int>(msgToSend.size()), 0) == SOCKET_ERROR) {
            std::cerr << "\nFailed to send message to server." << std::endl;
        }
        else {
            messageQueueService.ConfirmMessageDelivered("outgoing", msgToSend);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main() {
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
    serverAddr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "192.168.1.12", &serverAddr.sin_addr); // tvoja lokalna IP adresa

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection to server failed" << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to local server." << std::endl;

    ThreadPool threadPool(2);
    threadPool.enqueue([clientSocket]() { receiveMessages(clientSocket); });
    threadPool.enqueue([clientSocket]() { sendMessages(clientSocket); });

    while (globalShutdownFlag == "running") {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    closesocket(clientSocket);
    WSACleanup();

    std::cout << "Client has stopped." << std::endl;
    return 0;
}
