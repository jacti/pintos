#include <stdint.h>


typedef int32_t fixed_t;


#define F (1 << 14)


/**
 * @brief 정수 n을 고정소수점 fixed_t 타입으로 변환합니다.
 * @param n 변환할 int형 정수
 * @return fixed_t로 표현된 값 (n * F)
 */
#define CITOF(n) ((fixed_t)(n) * F)

/**
 * @brief 고정소수점 fixed_t 값을 정수로 변환합니다 (소수점 버림).
 * @param x 변환할 고정소수점 값
 * @return int로 변환된 값 (x / F)
 */
#define CFTOI(x) ((int)(x) >> 14)

/**
 * @brief 고정소수점 fixed_t 값을 정수로 변환합니다 (반올림).
 * @param x 변환할 고정소수점 값
 * @return 반올림된 int 값
 */
#define FTOI_N(x) (((x) >= 0) ? (((x) + (F / 2)) / F) : (((x) - (F / 2)) / F))

/**
 * @brief 고정소수점 값 x와 y를 더합니다.
 * @param x 고정소수점 값
 * @param y 고정소수점 값
 * @return x + y (fixed_t)
 */
#define ADDFF_F(x, y) ((x) + (y))

/**
 * @brief 고정소수점 값 x에서 y를 뺍니다.
 * @param x 고정소수점 값
 * @param y 고정소수점 값
 * @return x - y (fixed_t)
 */
#define SUBFF_F(x, y) ((x) - (y))

/**
 * @brief 고정소수점 값 x에 정수 n을 더합니다.
 * @param x 고정소수점 값
 * @param n int형 정수
 * @return x + n (fixed_t)
 */
#define ADDFI_F(x, n) ((x) + (CITOF(n)))

/**
 * @brief 고정소수점 값 x에서 정수 n을 뺍니다.
 * @param x 고정소수점 값
 * @param n int형 정수
 * @return x - n (fixed_t)
 */
#define SUBFI_F(x, n) ((x) - (CITOF(n)))

/**
 * @brief 고정소수점 값 x와 y를 곱합니다.
 * @param x 고정소수점 값
 * @param y 고정소수점 값
 * @return (x * y) / F 결과 (fixed_t)
 */
#define MUXFF_INT32(x, y) (((fixed_t)(x)) * (y) / F)

/**
 * @brief 고정소수점 값 x에 정수 n을 곱합니다.
 * @param x 고정소수점 값
 * @param n int형 정수
 * @return x * n (fixed_t)
 */
#define MUXFI_INT32(x, n) (((fixed_t)(x)) * (n))

/**
 * @brief 고정소수점 값 x를 y로 나눕니다.
 * @param x 고정소수점 값 (분자)
 * @param y 고정소수점 값 (분모)
 * @return (x / y) * F 결과 (fixed_t)
 */
#define DIVFF_INT32(x, y) (((fixed_t)(x)) * F / (y))

/**
 * @brief 고정소수점 값 x를 정수 n으로 나눕니다.
 * @param x 고정소수점 값
 * @param n int형 정수
 * @return x / n (fixed_t)
 */
#define DIVFI_INT32(x, n) ((x) / (n))
