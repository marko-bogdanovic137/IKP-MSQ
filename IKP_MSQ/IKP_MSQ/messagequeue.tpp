template <class T>
void MessageQueue<T>::enqueue(const T& item) {
    std::lock_guard<std::mutex> lock(mutex);
    queue.push(item);
    condition.notify_one();
}

template <class T>
T MessageQueue<T>::dequeue() {
    std::unique_lock<std::mutex> lock(mutex);
    condition.wait(lock, [this]() { return !queue.empty(); });
    T item = queue.front();
    queue.pop();
    return item;
}

template <class T>
bool MessageQueue<T>::tryDequeue(T& item) {
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty()) {
        return false;
    }
    item = queue.front();
    queue.pop();
    return true;
}

template <class T>
bool MessageQueue<T>::isEmpty(){
    std::lock_guard<std::mutex> lock(mutex);
    if(queue.empty())
    {
        return true;
    }
    else
    {
        return false;
    }
}