#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdio.h>
#include <stdlib.h>
#include <ev.h>

#ifdef __cplusplus
extern "C" {
#endif

// Initializes logging.
// Writes logs to descriptor 'fd' for log levels above or equal to 'level'.
// use_syslog参数
void logging_init(int fd, int level, unsigned flight_recorder_size, int syslog_flag);

// Initialize periodic timer to flush logs.
void logging_events_init(struct ev_loop *loop);
void logging_events_cleanup(struct ev_loop *loop);

// Cleans up and flushes open logs.
void logging_cleanup(void);

// Returns 1 if debug logging is enabled.
int logging_debug_enabled(void);

// Dump flight recorder.
void logging_flight_recorder_dump(void);

// Internal. Don't use.
void _log(const char *file, int line, int severity, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

enum LogSeverity {
  DOH_LOG_DEBUG,
  DOH_LOG_INFO,
  DOH_LOG_WARNING,
  DOH_LOG_ERROR,
  DOH_LOG_STATS,
  DOH_LOG_FATAL,
  DOH_LOG_MAX
};

#define LOG(level, ...) _log(__FILENAME__, __LINE__, level, __VA_ARGS__)
#define DLOG(...) _log(__FILENAME__, __LINE__, DOH_LOG_DEBUG, __VA_ARGS__)
#define ILOG(...) _log(__FILENAME__, __LINE__, DOH_LOG_INFO, __VA_ARGS__)
#define WLOG(...) _log(__FILENAME__, __LINE__, DOH_LOG_WARNING, __VA_ARGS__)
#define ELOG(...) _log(__FILENAME__, __LINE__, DOH_LOG_ERROR, __VA_ARGS__)
#define SLOG(...) _log(__FILENAME__, __LINE__, DOH_LOG_STATS, __VA_ARGS__)
#define FLOG(...) do { \
  _log(__FILENAME__, __LINE__, DOH_LOG_FATAL, __VA_ARGS__); \
  exit(1); /* for clang-tidy! */ \
} while(0)

#endif // _LOGGING_H_
