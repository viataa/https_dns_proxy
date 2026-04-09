#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "options.h"

// 配置文件解析结果
enum ConfigParseResult {
    CPR_SUCCESS,        // 成功
    CPR_FILE_NOT_FOUND, // 配置文件不存在
    CPR_PARSE_ERROR,    // 解析错误
    CPR_MEMORY_ERROR    // 内存错误
};

// Bit flags for Options.alloc_fields to track strdup-allocated strings
#define ALLOC_LISTEN_ADDR   (1u << 0)
#define ALLOC_USER          (1u << 1)
#define ALLOC_GROUP         (1u << 2)
#define ALLOC_BOOTSTRAP_DNS (1u << 3)
#define ALLOC_RESOLVER_URL  (1u << 4)
#define ALLOC_CURL_PROXY    (1u << 5)
#define ALLOC_SOURCE_ADDR   (1u << 6)
#define ALLOC_CA_INFO       (1u << 7)
#define ALLOC_LOGFILE       (1u << 8)
#define ALLOC_FALLBACK_DNS  (1u << 9)

#ifdef __cplusplus
extern "C" {
#endif

// 从配置文件加载选项
enum ConfigParseResult config_load(const char *config_file, struct Options *opt);

// 显示配置文件格式说明
void config_show_help(void);

#ifdef __cplusplus
}
#endif

#endif // _CONFIG_H_
