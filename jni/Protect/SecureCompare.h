#ifndef SECURE_COMPARE_H
#define SECURE_COMPARE_H

#include <cstdint>
#include <cstddef>

// 常量时间比较 —— 编译进 OLLVM 模块，不调用 libc memcmp
// 攻击者 hook memcmp 无法绕过此函数
namespace SecureCompare {

// 常量时间: 无论哪个字节不同都会遍历完全部
__attribute__((always_inline, noinline))
static inline int secure_memcmp(const void *a, const void *b, size_t len) {
    const volatile uint8_t *pa = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t *pb = static_cast<const volatile uint8_t*>(b);
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (pa[i] ^ pb[i]);
    }
    return (int)diff;
}

// 32位整数常量时间比较
__attribute__((always_inline))
static inline bool secure_u32_eq(uint32_t a, uint32_t b) {
    volatile uint32_t x = a ^ b;
    return x == 0;
}

// 安全清零
__attribute__((noinline))
static inline void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; i++) p[i] = 0;
}

} // namespace SecureCompare

#endif // SECURE_COMPARE_H
