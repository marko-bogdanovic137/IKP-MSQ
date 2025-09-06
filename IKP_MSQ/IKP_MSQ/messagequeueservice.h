#ifndef MESSAGE_QUEUE_SERVICE_H
#define MESSAGE_QUEUE_SERVICE_H

#include <string>

// Apstraktni interfejs za rad sa redovima poruka
class MessageQueueService {
public:
    virtual ~MessageQueueService() = default;

    virtual void SendMessage(const std::string& queueName, const void* message, int messageSize) = 0;
};

#endif // MESSAGE_QUEUE_SERVICE_H
