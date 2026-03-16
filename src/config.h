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
