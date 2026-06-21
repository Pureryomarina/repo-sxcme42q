#ifndef PROTECT_COMMON_H
#define PROTECT_COMMON_H

#include <android/log.h>

#ifndef ALOGD
#define ALOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, "Protect", fmt, ##__VA_ARGS__)
#endif
#ifndef ALOGI
#define ALOGI(fmt, ...) __android_log_print(ANDROID_LOG_INFO, "Protect", fmt, ##__VA_ARGS__)
#endif
#ifndef ALOGW
#define ALOGW(fmt, ...) __android_log_print(ANDROID_LOG_WARN, "Protect", fmt, ##__VA_ARGS__)
#endif
#ifndef ALOGE
#define ALOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR, "Protect", fmt, ##__VA_ARGS__)
#endif

#endif
