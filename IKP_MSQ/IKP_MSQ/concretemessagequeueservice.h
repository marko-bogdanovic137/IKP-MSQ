#ifndef CONCRETE_MESSAGE_QUEUE_SERVICE_H
#define CONCRETE_MESSAGE_QUEUE_SERVICE_H

#include "messagequeueservice.h"
#include "messagequeue.h"
#include <unordered_map>
#include <string>
#include <memory>

class ConcreteMessageQueueService : public MessageQueueService {
private:
	std::unordered_map < std::string, std::shared_ptr<MessageQueue<std::string>>> queues;


public:
	void SendMessage(const std::string& queueName, const void* message, int messageSize) override;

	// pristup redu prema imenu
	std::shared_ptr<MessageQueue<std::string>> GetQueue(const std::string& queueName);

	// Kreira red ako ne postoji
	void CreateQueue(const std::string& queueName);
};

#endif // CONCRETE_MESSAGE_QUEUE_SERVICE_H

