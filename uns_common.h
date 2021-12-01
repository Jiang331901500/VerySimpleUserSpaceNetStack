#ifndef __UNS_COMMON_H__
#define __UNS_COMMON_H__

#ifndef NO_DEBUG   // close debug
#define log printf
#else
#define log(x, ...)
#endif

typedef unsigned char _u8;
typedef unsigned short _u16;
typedef unsigned int _u32;

#define TCP_BUFFER_SIZE 16 * 1024
#define TCP_MAX_WIN_SIZE (TCP_BUFFER_SIZE>>1)

#endif