#include <string.h>

#ifndef MEMORY_H
#define MEMORY_H

template <typename T, typename... Args>
void cleanup(T t)
{
    if (t)
    {
        free(t);
    }
}

template <typename T, typename... Args>
void cleanup(T t, Args... args)
{
    if (t)
    {
        free(t);
    }
    
    cleanup(args...);
}

template <typename... Args>
void free_memory(Args... args)
{
    cleanup(args...);
}

#endif
