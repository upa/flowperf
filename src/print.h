#ifndef _PRINT_H_
#define _PRINT_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define SEVERITY_ERR		0
#define SEVERITY_WARN		1
#define SEVERITY_NOTICE	2
#define SEVERITY_INFO		3
#define SEVERITY_DEBUG		4

void set_print_severity(int severity);
int get_print_severity();

#define __print(fp, severity, prefix, fmt, ...)			\
	do {                                                             \
		if (severity <= get_print_severity()) {                  \
			fprintf(fp, prefix "[%s]: " fmt "\n", __func__, ##__VA_ARGS__); \
			fflush(fp);                                      \
		}                                                        \
	} while (0)

#define pr_err(fmt, ...) \
	__print(stderr, SEVERITY_ERR, "\e[31m[ERR]\e[m", fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) \
	__print(stderr, SEVERITY_WARN, "\e[33m[WARN]\e[m", fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
	__print(stderr, SEVERITY_NOTICE, "\e[35m[NOTICE]\e[m]", fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	__print(stderr, SEVERITY_INFO, "[INFO]", fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	__print(stderr, SEVERITY_DEBUG, "[DEBUG]", fmt, ##__VA_ARGS__)

#endif /* _PRINT_H_ */
