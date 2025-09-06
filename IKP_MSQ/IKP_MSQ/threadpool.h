#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <vector>
#include <queue>
#include <thread>
#include <functional>
#include <atomic>
#include <condition_variable>
#include <mutex>


class ThreadPool {
public:
    explicit ThreadPool(size_t numThreads);
    ~ThreadPool();

    void enqueue(std::function<void()> task);

private:
    // Radne niti
    std::vector<std::thread> workers;

    // Red zadataka
    std::queue<std::function<void()>> tasks;

    // Sinhronizacija
    std::mutex tasksMutex;
    std::condition_variable condition;

    // Kontrola rada niti
    bool stop;

    // Funkcija koja pokrece niti i obradjuje zadatke
    void worker();
};







#endif // THREADPOOL_H
