#ifndef CONCRETE_MESSAGE_QUEUE_SERVICE_H
#define CONCRETE_MESSAGE_QUEUE_SERVICE_H

#include "messagequeueservice.h"
#include "messagequeue.h"
#include <unordered_map>
#include <string>
#include <memory>

class ConcreteMessageQueueService : public MessageQueueService {
private:
    std::unordered_map<std::string, std::shared_ptr<MessageQueue<std::string>>> queues;
    std::mutex queuesMutex;
public:
    void SendMessage(const std::string& queueName, const void* message, int messageSize) override;
    std::shared_ptr<MessageQueue<std::string>> GetQueue(const std::string& queueName);
    void CreateQueue(const std::string& queueName);

    bool ConfirmMessageDelivered(const std::string& queueName, const std::string& message); // nova metoda
};


#endif // CONCRETE_MESSAGE_QUEUE_SERVICE_H

