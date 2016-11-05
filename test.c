#include <assert.h>
#include <string.h>

#include "aes.h"
#include "crackle.h"

void test_encrypt_sample_data(void) {
    connection_state_t state;
    memset(&state, 0, sizeof(state));

    uint8_t nonce[13] = { 0x00, };

    // sample data IV:
    uint8_t iv[8] = { 0x24, 0xAB, 0xDC, 0xBA, 0xBE, 0xBA, 0xAF, 0xDE , };

    memset(nonce, 0, 13);
    // nonce[0] = 1;
    memcpy(nonce + 5, iv, 8);

    // sample data session key:
    uint8_t sk[16] = { 0x99, 0xad, 0x1b, 0x52, 0x26, 0xa3, 0x7e, 0x3e, 0x05, 0x8e, 0x3b, 0x8e, 0x27, 0xc2, 0xc6, 0x66};

    // sample data message
    uint8_t pbuf[32] = {0x06,};  // plaintext
    uint8_t ebuf[32] = {0xa3,};  // crypted

    // sample data MAC
    uint8_t adata[16] = { 0x03, };

    uint8_t out[16];
    uint8_t auth_out[16];
    uint8_t auth[4] = { 0x4c, 0x13, 0xa4, 0x15, };

    int r = aes_ccm_ae(sk, 16, nonce,
                   4, pbuf, 1,
                   adata, 1, out, auth_out);

    assert(r == 0);
    assert(memcmp(out, ebuf, 1) == 0);
    assert(memcmp(auth_out, auth, 4) == 0);
}

void test_decrypt_sample_data(void) {
    int r;

    // sample data session key:
    uint8_t sk[16] = { 0x99, 0xad, 0x1b, 0x52, 0x26, 0xa3, 0x7e, 0x3e, 0x05, 0x8e, 0x3b, 0x8e, 0x27, 0xc2, 0xc6, 0x66};

    uint8_t ebuf[16] = {0xa3,};
    uint8_t auth[16] = { 0x4c, 0x13, 0xa4, 0x15 };
    uint8_t adata[16] = { 0x03, };
    uint8_t out[16];
    uint8_t nonce[13];

    uint8_t iv[8] = { 0x24, 0xAB, 0xDC, 0xBA, 0xBE, 0xBA, 0xAF, 0xDE , };

    memset(nonce, 0, 13);
    nonce[4] = 0x00; // slave -> master
    memcpy(nonce + 5, iv, 8);

    r = aes_ccm_ad(sk, 16, nonce,
                   4, ebuf, 1,
                   adata, 1, auth, out);

    assert(r == 0);
    assert(out[0] == 0x06);

    // ---

    ebuf[0] = 0x9f;
    auth[0] = 0xcd; auth[1] = 0xa7; auth[2] = 0xf4; auth[3] = 0x48;
    memset(nonce, 0, 13);
    nonce[4] = 0x80; // master -> slave
    memcpy(nonce + 5, iv, 8);

    r = aes_ccm_ad(sk, 16, nonce,
                   4, ebuf, 1,
                   adata, 1, auth, out);

    assert(r == 0);
    assert(out[0] == 0x06);
}

void test_calc_session_key(void) {
    connection_state_t state;
    memset(&state, 0, sizeof(state));

    uint8_t ltk[16] = { 0x4C, 0x68, 0x38, 0x41, 0x39, 0xF5, 0x74, 0xD8, 0x36, 0xBC, 0xF3, 0x4E, 0x9D, 0xFB, 0x01, 0xBF , };
    uint8_t skdm[8] = { 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1, 0x02, 0x13, };
    uint8_t skds[8] = { 0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, };
    uint8_t sk[16] = { 0x99, 0xad, 0x1b, 0x52, 0x26, 0xa3, 0x7e, 0x3e, 0x05, 0x8e, 0x3b, 0x8e, 0x27, 0xc2, 0xc6, 0x66};

    memcpy(state.stk, ltk, 16);
    memcpy(state.skdm, skdm, 8);
    memcpy(state.skds, skds, 8);
    calc_session_key(&state);

    assert(memcmp(state.session_key, sk, 16) == 0);
}

void test_calc_stk(void) {
    connection_state_t state;
    memset(&state, 0, sizeof(state));

    uint8_t mrand[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, };
    uint8_t srand[16] = { 0x00, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, };
    uint8_t stk[16]   = { 0x9a, 0x1f, 0xe1, 0xf0, 0xe8, 0xb0, 0xf4, 0x9b, 0x5b, 0x42, 0x16, 0xae, 0x79, 0x6d, 0xa0, 0x62, };

    memcpy(state.mrand, mrand, 16);
    memcpy(state.srand, srand, 16);
    calc_stk(&state, 0);

    assert(memcmp(state.stk, stk, 16) == 0);
}

void run_tests(void) {
    test_calc_stk();
    test_calc_session_key();
    test_encrypt_sample_data();
    test_decrypt_sample_data();
}
