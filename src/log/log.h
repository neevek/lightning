#ifndef LOG_H_
#define LOG_H_
#include <stdio.h>
#include <string.h>
#include <stdarg.h>    // for va_list, va_start and va_end
#include <sys/time.h>

#ifdef __ANDROID__
#include <android/log.h>
#endif

#define MAX_FMT_SIZE 0xFF
#define TIME_BUFFER_SIZE 24

#if !defined(__ANDROID__) && \
    (defined(LOG_VERBOSE) || \
     defined(LOG_DEBUG) || \
     defined(LOG_INFO) || \
     defined(LOG_WARN) || \
     defined(LOG_ERROR))
static char *strtime(char *buffer) {
    struct timeval now;
    gettimeofday(&now, NULL);

    size_t len = strftime(buffer, TIME_BUFFER_SIZE, "%Y-%m-%d %H:%M:%S.", 
        localtime(&now.tv_sec));
    int milli = now.tv_usec / 1000;
    sprintf(buffer + len, "%03d", milli);

    return buffer;
}
#endif

#if defined(LOG_VERBOSE)
#ifdef __ANDROID__
#define LOG_V(fmt, ...) \
{ \
  __android_log_print(ANDROID_LOG_VERBOSE, __FILE__, "%s#%d - " fmt "\n", \
      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
}
#else
#define LOG_V(fmt, ...) \
{ \
  char _Buf_[TIME_BUFFER_SIZE];  \
  fprintf(stderr, "%s [V] [%s:%d] %s - " fmt "\n", strtime(_Buf_), __FILE__, \
      __LINE__, __FUNCTION__, ##__VA_ARGS__); \
}
#endif
#else
#define LOG_V(fmt, ...)
#endif

#if defined(LOG_VERBOSE) || defined(LOG_DEBUG)
#ifdef __ANDROID__
#define LOG_D(fmt, ...) \
{ \
  __android_log_print(ANDROID_LOG_DEBUG, __FILE__, "%s#%d - " fmt "\n", \
      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
}
#else
#define LOG_D(fmt, ...) \
{ \
  char _Buf_[TIME_BUFFER_SIZE];  \
  fprintf(stderr, "%s [D] [%s:%d] %s - " fmt "\n", strtime(_Buf_), __FILE__, \
      __LINE__, __FUNCTION__, ##__VA_ARGS__); \
}
#endif
#else
#define LOG_D(fmt, ...)
#endif

#if defined(LOG_VERBOSE) || defined(LOG_DEBUG) || defined(LOG_INFO)
#ifdef __ANDROID__
#define LOG_I(fmt, ...) \
{ \
  __android_log_print(ANDROID_LOG_INFO, __FILE__, "%s#%d - " fmt "\n", \
      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
}
#else
#define LOG_I(fmt, ...) \
{ \
  char _Buf_[TIME_BUFFER_SIZE];  \
  fprintf(stderr, "%s [I] [%s:%d] %s - " fmt "\n", strtime(_Buf_), __FILE__, \
      __LINE__, __FUNCTION__, ##__VA_ARGS__); \
}
#endif
#else
#define LOG_I(fmt, ...)
#endif

#if defined(LOG_VERBOSE) || defined(LOG_DEBUG) || defined(LOG_INFO) || \
    defined(LOG_WARN)
#ifdef __ANDROID__
#define LOG_W(fmt, ...) \
{ \
  __android_log_print(ANDROID_LOG_WARN, __FILE__, "%s#%d - " fmt "\n", \
      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
}
#else
#define LOG_W(fmt, ...) \
{ \
  char _Buf_[TIME_BUFFER_SIZE];  \
  fprintf(stderr, "%s [W] [%s:%d] %s - " fmt "\n", strtime(_Buf_), __FILE__, \
      __LINE__, __FUNCTION__, ##__VA_ARGS__); \
}
#endif
#else
#define LOG_W(fmt, ...)
#endif

#if defined(LOG_VERBOSE) || defined(LOG_DEBUG) || defined(LOG_INFO) || \
    defined(LOG_WARN) || defined(LOG_ERROR)
#ifdef __ANDROID__
#define LOG_E(fmt, ...) \
{ \
  __android_log_print(ANDROID_LOG_ERROR, __FILE__, "%s#%d - " fmt "\n", \
      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
}
#else
#define LOG_E(fmt, ...) \
{ \
  char _Buf_[TIME_BUFFER_SIZE];  \
  fprintf(stderr, "%s [E] [%s:%d] %s - " fmt "\n", strtime(_Buf_), __FILE__, \
      __LINE__, __FUNCTION__, ##__VA_ARGS__); \
}
#endif
#else
#define LOG_E(fmt, ...)
#endif

#endif /* end of include guard: LOG_H_ */
