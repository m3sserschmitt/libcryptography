#include <string.h>


#ifndef MEMORY_H
#define MEMORY_H

template <typename T, typename... Args>
void cleanup(T t) {
    free(t);
}

template <typename T, typename... Args>
void cleanup(T t, Args ...args) {
    free(t);
    cleanup(t, args...);
}

template <typename... Args>
void free_memory(Args... args) {
    cleanup(args...);
}

#endif