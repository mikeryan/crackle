#include <assert.h>
#include <err.h>
#include <stdint.h>
#include <string.h>

#include <pcap/pcap.h>

typedef struct _crackle_state_t {
    int connect_found;
    int preq_found;
    int pres_found;
    int confirm_found;
    int random_found;

    // field from connect packet
    uint8_t ia[6], ra[6];
    int iat, rat;

    uint8_t preq[7];
    uint8_t pres[7];

    uint8_t mconfirm[16], sconfirm[16];
    uint8_t mrand[16], srand[16];
} crackle_state_t;

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

void parse_btle(crackle_state_t *state, const u_char *bytes, size_t len) {
    const uint32_t adv_aa = 0x8e89bed6;
    uint32_t aa;

    assert(state != NULL);

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
    }
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
    parse_btle(state, bytes + header_len, h->caplen - header_len);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap;
    crackle_state_t state;
    int err_count = 0;

    // reset state
    memset(&state, 0, sizeof(state));

    if (argc < 2)
        errx(1, "Usage: %s <input.pcap>", argv[0]);

    cap = pcap_open_offline(argv[1], errbuf);
    if (cap == NULL)
        errx(1, "%s", errbuf);

    pcap_dispatch(cap, 0, packet_handler, (u_char *)&state);

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
    if (err_count > 0) {
        printf("Giving up due to %d error%s\n", err_count, err_count == 1 ? "" : "s");
        return 1;
    }

    return 0;
}
