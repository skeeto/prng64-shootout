/* C99 Blowfish implementation
 *
 * This is free and unencumbered software released into the public domain.
 */
#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

#define BLOWFISH_BLOCK_LENGTH    8
#define BLOWFISH_SALT_LENGTH     16
#define BLOWFISH_DIGEST_LENGTH   24
#define BLOWFISH_MAX_KEY_LENGTH  72
#define BLOWFISH_MAX_COST        63

struct blowfish {
    uint32_t p[18];
    uint32_t s[4][256];
};

/* Initialize a cipher context with the given key.
 *
 * The maximum key length is 72 bytes. Generally the key length should
 * not exceed 56 bytes since the last 16 bytes do not affect every bit
 * of each subkey.
 */
void blowfish_init(struct blowfish *, const void *key, int len);

/* Encrypt 16 rounds. */
void blowfish_encrypt16(struct blowfish *, uint32_t *, uint32_t *);

/* Encrypt 4 rounds. */
void blowfish_encrypt4(struct blowfish *, uint32_t *, uint32_t *);

#endif
