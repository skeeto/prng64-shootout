#define _POSIX_SOURCE 1
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include <getopt.h>
#include <unistd.h> // alarm()

#include "rc4.h"
#include "mt64.h"
#include "blowfish.h"

#define UNROLL 8           /* Iterations between alarm checks */
#define SECONDS 1          /* Seconds spent on each test */
#define NSAMPLES 8         /* Number of samples per generator */

#define N (64UL * 1024 * 1024)
static volatile uint64_t buffer[N];
static volatile sig_atomic_t running;

void
alarm_handler(int signum)
{
    (void)signum;
    running = 0;
}

#define XSTR(s) str(s)
#define STR(s) #s

#define DEFINE_BENCH(name, setup, rand64) \
    static void \
    name##_bench(void) \
    { \
        unsigned long long best = 0; \
        for (int i = 0; i < NSAMPLES; i++) { \
            running = 1; \
            unsigned long long c = 0; \
            setup(); \
            signal(SIGALRM, alarm_handler); \
            alarm(SECONDS); \
            while (running) { \
                for (int i = 0; i < UNROLL; i++) { \
                    rand64(buffer[c++ % N]); \
                } \
            } \
            if (c > best) \
                best = c; \
        } \
        double rate = 8.0 * best / SECONDS / 1024.0 / 1024.0; \
        printf("%-20s%f MB/s\n", STR(name), rate); \
        fflush(stdout); \
    } \
\
    static void \
    name##_pump(void) \
    { \
        setup(); \
        uint64_t r; \
        do { \
            rand64(r); \
        } while (fwrite(&r, sizeof(r), 1, stdout)); \
    }

static uint64_t
xorshift64star(uint64_t s[1])
{
    uint64_t x = s[0];
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s[0] = x;
    return x * UINT64_C(0x2545f4914f6cdd1d);
}

static uint64_t
xorshift128plus(uint64_t s[2])
{
    uint64_t x = s[0];
    uint64_t y = s[1];
    s[0] = y;
    x ^= x << 23;
    s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
    return s[1] + y;
}

static uint64_t
xoroshiro128plus(uint64_t s[2])
{
    uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    uint64_t result = s0 + s1;
    s1 ^= s0;
    s[0] = ((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14);
    s[1] = (s1 << 36) | (s1 >> 28);
    return result;
}

static uint64_t
spcg64(uint64_t s[2])
{
    uint64_t m  = 0x9b60933458e17d7d;
    uint64_t a0 = 0xd737232eeccdf7ed;
    uint64_t a1 = 0x8b260b70b8e98891;
    uint64_t p0 = s[0];
    uint64_t p1 = s[1];
    s[0] = p0 * m + a0;
    s[1] = p1 * m + a1;
    int r0 = 29 - (p0 >> 61);
    int r1 = 29 - (p1 >> 61);
    uint64_t high = p0 >> r0;
    uint64_t low  = p1 >> r1;
    return (high << 32) | low;
}

static uint64_t
pcg64(uint64_t s[2])
{
    uint64_t m  = 0x5851f42d4c957f2d;
    uint64_t a0 = 0xd737232eeccdf7ed;
    uint64_t a1 = 0x8b260b70b8e98891;
    uint64_t p0 = s[0];
    uint64_t p1 = s[1];
    s[0] = p0 * m + a0;
    s[1] = p1 * m + a1;
    uint32_t x0 = ((p0 >> 18) ^ p0) >> 27;
    uint32_t x1 = ((p1 >> 18) ^ p1) >> 27;
    uint32_t r0 = p0 >> 59;
    uint32_t r1 = p1 >> 59;
    uint64_t high = (x0 >> r0) | (x0 << ((-r0) & 31u));
    uint64_t low  = (x1 >> r1) | (x1 << ((-r1) & 31u));
    return (high << 32) | low;
}

#define BASELINE_SETUP()
#define BASELINE_RAND(dst) \
    dst = 0

#define XORSHIFT64STAR_SETUP() \
    uint64_t state = 0xdeadbeefcafebabe
#define XORSHIFT64STAR_RAND(dst) \
    dst = xorshift64star(&state)

#define XORSHIFT128PLUS_SETUP() \
    uint64_t state[] = {0xdeadbeefcafebabe, 0x8badf00dbaada555}
#define XORSHIFT128PLUS_RAND(dst) \
    dst = xorshift128plus(state)

#define XOROSHIRO128PLUS_SETUP() \
    uint64_t state[] = {0xdeadbeefcafebabe, 0x8badf00dbaada555}
#define XOROSHIRO128PLUS_RAND(dst) \
    dst = xoroshiro128plus(state)

#define BLOWFISHCBC_SETUP() \
    struct blowfish ctx[1]; \
    blowfish_init(ctx, "", 1); \
    uint32_t state[2] = {0, 0}
#define BLOWFISHCBC16_RAND(dst) \
    blowfish_encrypt16(ctx, state + 0, state + 1); \
    dst = ((uint64_t)state[1] << 32) | state[0]
#define BLOWFISHCBC4_RAND(dst) \
    blowfish_encrypt4(ctx, state + 0, state + 1); \
    dst = ((uint64_t)state[1] << 32) | state[0]

#define BLOWFISHCTR_SETUP() \
    struct blowfish ctx[1]; \
    blowfish_init(ctx, "seed", 5); \
    uint64_t ctr = 0; \
    uint32_t block[2]
#define BLOWFISHCTR16_RAND(dst) \
    block[0] = ctr >> 32; \
    block[1] = ctr++; \
    blowfish_encrypt16(ctx, block + 0, block + 1); \
    dst = ((uint64_t)block[1] << 32) | block[0]
#define BLOWFISHCTR4_RAND(dst) \
    block[0] = ctr >> 32; \
    block[1] = ctr++; \
    blowfish_encrypt4(ctx, block + 0, block + 1); \
    dst = ((uint64_t)block[1] << 32) | block[0]

#define MT64_SETUP() \
    struct mt64 mt64[1]; \
    mt_init(mt64, UINT64_C(0xdeadbeefcafebabe))
#define MT64_RAND(dst) \
    dst = mt_rand(mt64)

#define SPCG64_SETUP() \
    uint64_t state[] = {0xdeadbeefcafebabe, 0x8badf00dbaada555}
#define SPCG64_RAND(dst) \
    dst = spcg64(state)

#define PCG64_SETUP() \
    uint64_t state[] = {0xdeadbeefcafebabe, 0x8badf00dbaada555}
#define PCG64_RAND(dst) \
    dst = pcg64(state)

#define RC4_SETUP() \
    struct rc4 rc4[1]; \
    rc4_init(rc4, "seed", 5); \
    uint64_t v
#define RC4_RAND(dst) \
    rc4_rand(rc4, &v, sizeof(v)); \
    dst = v

DEFINE_BENCH(baseline, BASELINE_SETUP, BASELINE_RAND);
DEFINE_BENCH(xorshift64star, XORSHIFT64STAR_SETUP, XORSHIFT64STAR_RAND);
DEFINE_BENCH(xorshift128plus, XORSHIFT128PLUS_SETUP, XORSHIFT128PLUS_RAND);
DEFINE_BENCH(xoroshiro128plus, XOROSHIRO128PLUS_SETUP, XOROSHIRO128PLUS_RAND);
DEFINE_BENCH(blowfishcbc16, BLOWFISHCBC_SETUP, BLOWFISHCBC16_RAND);
DEFINE_BENCH(blowfishcbc4, BLOWFISHCBC_SETUP, BLOWFISHCBC4_RAND);
DEFINE_BENCH(blowfishctr16, BLOWFISHCTR_SETUP, BLOWFISHCTR16_RAND);
DEFINE_BENCH(blowfishctr4, BLOWFISHCTR_SETUP, BLOWFISHCTR4_RAND);
DEFINE_BENCH(mt64, MT64_SETUP, MT64_RAND);
DEFINE_BENCH(spcg64, SPCG64_SETUP, SPCG64_RAND);
DEFINE_BENCH(pcg64, PCG64_SETUP, PCG64_RAND);
DEFINE_BENCH(rc4, RC4_SETUP, RC4_RAND);

int
main(int argc, char **argv)
{
    static const struct {
        void (*bench)(void);
        void (*pump)(void);
        const char name[24];
    } prngs[] = {
        {baseline_bench,         baseline_pump,         "baseline"},
        {xorshift64star_bench,   xorshift64star_pump,   "xorshift64star"},
        {xorshift128plus_bench,  xorshift128plus_pump,  "xorshift128plus"},
        {xoroshiro128plus_bench, xoroshiro128plus_pump, "xoroshiro128plus"},
        {blowfishcbc16_bench,    blowfishcbc16_pump,    "blowfishcbc16"},
        {blowfishcbc4_bench,     blowfishcbc4_pump,     "blowfishcbc4"},
        {blowfishctr16_bench,    blowfishctr16_pump,    "blowfishctr16"},
        {blowfishctr4_bench,     blowfishctr4_pump,     "blowfishctr4"},
        {mt64_bench,             mt64_pump,             "mt64"},
        {spcg64_bench,           spcg64_pump,           "spcg64"},
        {pcg64_bench,            pcg64_pump,            "pcg64"},
        {rc4_bench,              rc4_pump,              "rc4"},
    };
    static const int nprngs = sizeof(prngs) / sizeof(*prngs);

    /* Options */
    int g = -1;

    int option;
    while ((option = getopt(argc, argv, "g:h")) != -1) {
        switch (option) {
            case 'g':
                g = atoi(optarg);
                if (g < 0 || g > nprngs) {
                    fprintf(stderr, "invalid -g argument: %d\n", g);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'h':
                puts("speedtest [-g n] [-h]");
                for (int i = 0; i < nprngs; i++)
                    printf("%-2d %s\n", i, prngs[i].name);
                exit(EXIT_SUCCESS);
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (g != -1) {
        prngs[g].pump();
    } else {
        for (int i = 0; i < nprngs; i++)
            prngs[i].bench();
    }
}
