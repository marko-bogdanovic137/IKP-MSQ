#ifndef SERVER_H
#define SERVER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include "../IKP_MSQ/MessageQueue.h"
#include "../IKP_MSQ/concretemessagequeueservice.h"
#include "../IKP_MSQ/ThreadPool.h"

#pragma comment(lib, "ws2_32.lib")

class Server {
private:
    std::string serverAddress;      // Adresa servera
    int port;                       // Port servera
    std::atomic<bool> running;      // Indikator da li server radi
    ThreadPool threadPool;          // Thread pool za upravljanje nitima
    bool isClient;                  // Indikator da li server inicira konekciju ili se povezuje
    bool connectToOtherServer;

    ConcreteMessageQueueService messageQueueService;

    MessageQueue<std::string> sendingQueue;     // Red za slanje poruka primljenih od klijenta (lokalni klijenti)
    MessageQueue<std::string> serverQueue;      // Red za slanje poruka drugom serveru

    // ACK / pending map za reliable delivery
    std::mutex pendingMutex;
    std::unordered_map<std::string, int> pendingAcks; // msgId -> attempts (present => waiting ACK)
    std::atomic<unsigned long long> msgCounter;

    // Socket-handling
    void receiveFromServer(SOCKET serverSocket);   // prima poruke od drugog servera
    void forwardToServer(SOCKET serverSocket);     // šalje poruke drugom serveru
    void handleClientConnection();                 // Metoda za rukovanje klijentom / accept
    void handleServerConnection();                 // Metoda za konektovanje ka drugom serveru (outbound)
    void receiveFromClient(SOCKET clientSocket);   // Metoda za primanje poruke od klijenta
    void forwardToClient(SOCKET clientSocket);     // Metoda za prosledjivanje poruke klijentu

    // Helpers
    std::string GenerateMessageID();
    bool isIncomingServerSocket(SOCKET sock, std::string& handshakeOut); // classify accepted socket

public:
    Server(const std::string& serverAddress, int port, bool connectToOtherServer = false, size_t threadPoolSize = 8);
    ~Server();

    // Metoda za slanje poruka u red (message queue service)
    void SendToQueue(const std::string& queueName, const std::string& message);

    void StartServerConnection();

    // Start i stop servera
    void start();
    void stop();
};

#endif // SERVER_H
