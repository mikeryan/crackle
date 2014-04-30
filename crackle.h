#ifndef __CRACKLE_H__
#define __CRACKLE_H__

#include <stdint.h>
#include <pcap.h>

typedef struct _crackle_state_t crackle_state_t;

// packet handler (called after a packet is sanity checked)
typedef void (*btle_handler_t)(crackle_state_t *state,
                               const struct pcap_pkthdr *h,
                               const uint8_t *bytes,
                               off_t offset,
                               size_t len);

struct _crackle_state_t {
    int connect_found;
    int preq_found;
    int pres_found;
    int confirm_found;
    int random_found;
    int enc_req_found;
    int enc_rsp_found;

    btle_handler_t btle_handler;

    // field from connect packet
    uint32_t aa;
    uint8_t ia[6], ra[6];
    int iat, rat;

    uint8_t preq[7];
    uint8_t pres[7];

    uint8_t mconfirm[16], sconfirm[16];
    uint8_t mrand[16], srand[16];

    // encryption request fields
    uint8_t rand[8];
    uint8_t ediv[2];
    uint8_t skdm[8];
    uint8_t ivm[4];

    // encryption response fields
    uint8_t skds[8];
    uint8_t ivs[4];

    uint8_t tk[16];
    uint8_t stk[16];
    uint8_t session_key[16];
    uint8_t iv[8];

    /* decryption */
    int decryption_active;
    pcap_dumper_t *dumper;
    int total_processed;
    int total_decrypted;

    uint64_t packet_counter[2]; // 0: master, 1: slave
};

void calc_stk(crackle_state_t *state, uint32_t numeric_key);
void calc_session_key(crackle_state_t *state);

#endif /* __CRACKLE_H__ */
