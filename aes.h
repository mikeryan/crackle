/*
 * AES functions
 * Copyright (c) 2003-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stdlib.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define AES_BLOCK_SIZE 16

void * aes_encrypt_init(const u8 *key, size_t len);
void aes_encrypt(void *ctx, const u8 *plain, u8 *crypt);
void aes_encrypt_deinit(void *ctx);
void * aes_decrypt_init(const u8 *key, size_t len);
void aes_decrypt(void *ctx, const u8 *crypt, u8 *plain);
void aes_decrypt_deinit(void *ctx);

int aes_ccm_ae(const u8 *key, size_t key_len, const u8 *nonce,
               size_t M, const u8 *plain, size_t plain_len,
               const u8 *aad, size_t aad_len, u8 *crypt, u8 *auth);
int aes_ccm_ad(const u8 *key, size_t key_len, const u8 *nonce,
               size_t M, const u8 *crypt, size_t crypt_len,
               const u8 *aad, size_t aad_len, const u8 *auth, u8 *plain);

#endif /* AES_H */
