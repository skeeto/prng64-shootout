#ifndef ARC4_H
#define ARC4_H

struct rc4 {
    unsigned char s[256];
    int i, j;
};

static void
rc4_init(struct rc4 *rc4, void *key, int len)
{
    unsigned char *s = rc4->s;
    for (int i = 0; i < 256; i++)
        s[i] = i;
    rc4->i = 0;
    rc4->j = 0;

    int j = 0;
    unsigned char *k = key;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + k[i % len]) % 256;
        int t = s[i];
        s[i] = s[j];
        s[j] = t;
    }
}

static void
rc4_rand(struct rc4 *rc4, void *buf, size_t len)
{
    unsigned char *o = buf;
    unsigned char *s = rc4->s;
    int i = rc4->i;
    int j = rc4->j;
    for (size_t b = 0; b < len; b++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        int t = s[i];
        s[i] = s[j];
        s[j] = t;
        o[b] = s[(s[i] + s[j]) % 256];
    }
    rc4->i = i;
    rc4->j = j;
}

#endif
