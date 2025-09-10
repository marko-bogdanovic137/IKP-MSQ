#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <chrono>
#include <algorithm>
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

void receiveMessages(SOCKET clientSocket) {
    while (running) {
        std::string msg;
        if (!recvMessage(clientSocket, msg)) {
            std::cerr << "\nDisconnected from server." << std::endl;
            running = false;
            break;
        }

        if (msg.empty()) continue; // ignoriši prazne frame-ove

        if (msg.rfind("ACK|", 0) == 0) {
            std::cout << "\n[DEBUG] (client) Ignored server ACK: " << msg << std::endl;
            continue;
        }

        size_t firstSep = msg.find('|');
        if (firstSep != std::string::npos) {
            std::string firstTok = msg.substr(0, firstSep);
            bool firstIsNumeric = !firstTok.empty() &&
                std::all_of(firstTok.begin(), firstTok.end(), [](unsigned char c) { return std::isdigit(c); });

            if (firstIsNumeric) {
                size_t secondSep = msg.find('|', firstSep + 1);
                if (secondSep != std::string::npos) {
                    std::string secondTok = msg.substr(firstSep + 1, secondSep - (firstSep + 1));
                    if (secondTok == "CLIENT") {
                        size_t thirdSep = msg.find('|', secondSep + 1);
                        if (thirdSep != std::string::npos) {
                            std::string ip = msg.substr(secondSep + 1, thirdSep - (secondSep + 1));
                            std::string payload = msg.substr(thirdSep + 1);
                            std::cout << "\n[" << FRIEND << "]: " << payload << std::endl;
                            continue;
                        }
                    }
                }
            }
        }

        // fallback: normal message
        std::cout << "\n" << msg << std::endl;
    }
}




void sendMessages(SOCKET clientSocket, const std::string& myIp) {
    std::string message;
    const size_t MAX_MESSAGE_LENGTH = 512;

    try {
        while (running) {
            std::cout << "\n(type 'exit' to quit) [Me]: ";
            std::getline(std::cin, message);
            if (!running) break;

            if (message == "exit") {
                // pošalji exit poruku i izađi
                sendMessage(clientSocket, std::string("SYSTEM|exit"));
                running = false;
                break;
            }

            if (message.length() > MAX_MESSAGE_LENGTH) {
                std::cerr << "Message too long (max 512 chars)." << std::endl;
                continue;
            }

            // pošalji sa IP prefiksom (klijent šalje payload; server će dodatno tagovati)
            std::string messageWithIp = myIp + ": " + message;
            if (!sendMessage(clientSocket, messageWithIp)) {
                std::cerr << "\nFailed to send message to server. Error: " << WSAGetLastError() << std::endl;
            }
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "[EXCEPTION] sendMessages: " << ex.what() << std::endl;
        running = false;
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
