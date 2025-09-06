#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <queue>
#include <string>
#include <mutex>
#include <condition_variable>

template <class T>
class MessageQueue {
private:
	std::queue<T> queue;
	std::mutex mutex;
	std::condition_variable condition;

public:
	void enqueue(const T& item);
	T dequeue();
	bool tryDequeue(T& item);
	bool isEmpty();
};

#include "messagequeue.tpp"

#endif // MESSAGE_QUEUE_H

