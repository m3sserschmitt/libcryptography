/**
 * \file mem.h
 * \brief Memory allocation & free.
*/

#include "typedefs.h"

#include <cstring>

#ifndef MEM_H
#define MEM_H

/**
 * Allocates memory.
 * 
 * @param to: buffer to allocate memory;
 * @param size: number of bytes needed;
 */
template <class T>
inline void allocate_memory(T **to, SIZE size) {
    *to = (T *) malloc(size * sizeof(T));
    memset(*to, 0, size);

    return;
}

template <typename T, typename... Args>
void memory_cleanup(T t)
{
    if (t)
    {
        free(t);
    }
}

template <typename T, typename... Args>
void memory_cleanup(T t, Args... args)
{
    if (t)
    {
        free(t);
    }
    
    memory_cleanup(args...);
}

/**
 * Frees memory allocated by allocate_memory.
 * 
 * @param args: pointers to memory blocks;
 */
template <typename... Args>
void free_memory(Args... args)
{
    memory_cleanup(args...);
}

#endif