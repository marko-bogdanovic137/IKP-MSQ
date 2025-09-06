#include "pch.h"
#include "ConcreteMessageQueueService.h"

struct QueueMessage {
    std::string data;
    bool delivered;

    QueueMessage(const void* msg, int size)
        : data(static_cast<const char*>(msg), size), delivered(false) {
    }
};

void ConcreteMessageQueueService::SendMessage(const std::string& queueName, const void* message, int messageSize) {
    if (queues.find(queueName) == queues.end()) {
        CreateQueue(queueName);
    }


    QueueMessage msg(message, messageSize);
    queues[queueName]->enqueue(msg.data); 
}

std::shared_ptr<MessageQueue<std::string>> ConcreteMessageQueueService::GetQueue(const std::string& queueName) {
    if (queues.find(queueName) != queues.end()) {
        return queues[queueName];
    }
    return nullptr;
}

void ConcreteMessageQueueService::CreateQueue(const std::string& queueName) {
    queues[queueName] = std::make_shared<MessageQueue<std::string>>();
}
