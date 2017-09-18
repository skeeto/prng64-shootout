#ifndef MT_H
#define MT_H

#define MT_W  64
#define MT_N  312
#define MT_M  156
#define MT_R  31
#define MT_A  UINT64_C(0xb5026f5aa96619e9)
#define MT_U  29
#define MT_D  UINT64_C(0x5555555555555555)
#define MT_S  17
#define MT_B  UINT64_C(0x71d67fffeda60000)
#define MT_T  37
#define MT_C  UINT64_C(0xfff7eee000000000)
#define MT_L  43
#define MT_F  UINT64_C(0x5851f42d4c957f2d)
#define MT_LM UINT64_C(0x000000007fffffff)
#define MT_UM UINT64_C(0xffffffff80000000)
#define MT_UM UINT64_C(0xffffffff80000000)

struct mt64 {
    uint64_t v[MT_N];
    int i;
};

static void
mt_init(struct mt64 *mt, uint64_t seed) {
    mt->i = MT_N;
    mt->v[0] = seed;
    for (int i = 1; i < MT_N; i++)
        mt->v[i] = MT_F * (mt->v[i - 1] ^ (mt->v[i - 1] >> (MT_W - 2))) + i;
}
 
static uint64_t
mt_rand(struct mt64 *mt)
{
    if (mt->i >= MT_N) {
        for (int i = 0; i < MT_N; i++) {
            uint64_t x = (mt->v[i] & MT_UM) + (mt->v[(i + 1) % MT_N] & MT_LM);
            uint64_t xa = (x >> 1) ^ ((x & 1) * MT_A);
            mt->v[i] = mt->v[(i + MT_M) % MT_N] ^ xa;
        }
        mt->i = 0;
    }
    uint64_t y = mt->v[mt->i++];
    y = y ^ ((y >> MT_U) & MT_D);
    y = y ^ ((y << MT_S) & MT_B);
    y = y ^ ((y << MT_T) & MT_C);
    y = y ^ (y >> MT_L);
    return y;
}

#endif
