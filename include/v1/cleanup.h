#include <string.h>

#ifndef MEMORY_H
#define MEMORY_H

template <typename T, typename... Args>
void cryptography_cleanup(T t)
{
    if (t)
    {
        free(t);
    }
}

template <typename T, typename... Args>
void cryptography_cleanup(T t, Args... args)
{
    if (t)
    {
        free(t);
    }
    
    cleanup(args...);
}

template <typename... Args>
void cryptography_free(Args... args)
{
    cleanup(args...);
}

#endif
