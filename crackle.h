#ifndef __CRACKLE_H__
#define __CRACKLE_H__

#include <stdint.h>
#include <pcap.h>

typedef struct _crackle_state_t crackle_state_t;
typedef struct _connection_state_t connection_state_t;
typedef struct _encrypted_packet_t encrypted_packet_t;

// packet handler (called after a packet is sanity checked)
typedef void (*btle_handler_t)(crackle_state_t *state,
                               const struct pcap_pkthdr *h,
                               const uint8_t *bytes,
                               off_t offset,
                               size_t len);

struct _encrypted_packet_t {
    unsigned pcap_idx;

    uint8_t flags;
    uint8_t *enc_data;
    size_t enc_data_len;
    uint8_t *dec_data;
    size_t dec_data_len;
};

struct _connection_state_t {
    int connect_found;
    int preq_found;
    int pres_found;
    int confirm_found;
    int random_found;
    int enc_req_found;
    int enc_rsp_found;
    int start_enc_req_found;

    // LE Secure Connections
    int pairing_public_key_found;
    int pairing_dhkey_check_found;

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

    // post-decryption
    int ltk_found;
    uint8_t ltk[16];

    // all likely encrypted packets extracted from PCAP
    encrypted_packet_t *packets;
    unsigned num_packets;
    size_t packets_size;
    unsigned decrypted_packets;
};

struct _crackle_state_t {
    btle_handler_t btle_handler;

    unsigned pcap_idx;

    int verbose;

    /* decryption */
    pcap_dumper_t *dumper;
    int total_processed;
    int total_decrypted;

    // list of all succesfully decrypted packets + index into list
    encrypted_packet_t *all_decrypted;
    unsigned dec_idx;

    connection_state_t *conn;
    unsigned current_conn;
    unsigned total_conn;
};

void calc_stk(connection_state_t *state, uint32_t numeric_key);
void calc_session_key(connection_state_t *state);

#endif /* __CRACKLE_H__ */
