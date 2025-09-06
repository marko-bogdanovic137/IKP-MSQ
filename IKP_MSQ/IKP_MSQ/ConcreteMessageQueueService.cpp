#include "pch.h"
#include "concretemessagequeueservice.h"
#include <algorithm>


void ConcreteMessageQueueService::SendMessage(const std::string& queueName, const void* message, int messageSize) {
    std::string msg(static_cast<const char*>(message), messageSize);

    std::lock_guard<std::mutex> lock(queuesMutex);

    if (queues.find(queueName) == queues.end()) {
        CreateQueue(queueName);
    }

    queues[queueName]->enqueue(msg);
}

std::shared_ptr<MessageQueue<std::string>> ConcreteMessageQueueService::GetQueue(const std::string& queueName) {
    std::lock_guard<std::mutex> lock(queuesMutex);

    auto it = queues.find(queueName);
    if (it != queues.end()) {
        return it->second;
    }
    return nullptr;
}

void ConcreteMessageQueueService::CreateQueue(const std::string& queueName) {
    std::lock_guard<std::mutex> lock(queuesMutex);
    queues[queueName] = std::make_shared<MessageQueue<std::string>>();
}

bool ConcreteMessageQueueService::ConfirmMessageDelivered(const std::string& queueName, const std::string& message) {
    std::lock_guard<std::mutex> lock(queuesMutex);

    auto it = queues.find(queueName);
    if (it == queues.end()) return false;

    auto queue = it->second;

    std::vector<std::string> temp;
    bool found = false;

    while (!queue->isEmpty()) {
        std::string msg = queue->dequeue();
        if (!found && msg == message) {
            found = true; 
            continue;
        }
        temp.push_back(msg);
    }

    for (auto& msg : temp) {
        queue->enqueue(msg);
    }

    return found;
}
