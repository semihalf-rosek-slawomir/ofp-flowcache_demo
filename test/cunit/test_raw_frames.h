/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#ifndef __TEST_RAW_FRAMES_H__
#define __TEST_RAW_FRAMES_H__

/* Frame (106 bytes) */
static uint8_t tcp_frame[106] = {
0x08, 0x00, 0x27, 0xae, 0x3e, 0xd3, 0x08, 0x00, /* ..'.>... */
0x27, 0x00, 0xa8, 0x1e, 0x08, 0x00, 0x45, 0x00, /* '.....E. */
0x00, 0x5c, 0x00, 0x93, 0x40, 0x00, 0x80, 0x06, /* .\..@... */
0x07, 0xed, 0xc0, 0xa8, 0x38, 0x65, 0xc0, 0xa8, /* ....8e.. */
0x38, 0x66, 0xd1, 0x9e, 0x00, 0x16, 0x3f, 0xc9, /* 8f....?. */
0x7a, 0x8a, 0xee, 0x16, 0x51, 0xe9, 0x50, 0x18, /* z...Q.P. */
0x3f, 0xff, 0xb5, 0xf0, 0x00, 0x00, 0xb3, 0x3a, /* ?......: */
0x5c, 0xa0, 0x8e, 0x61, 0xff, 0x00, 0xd9, 0xbd, /* \..a.... */
0x20, 0x52, 0x08, 0xd1, 0xf9, 0xcc, 0x5b, 0xc8, /*  R....[. */
0x18, 0x1d, 0xee, 0x01, 0xd6, 0x34, 0x61, 0xf8, /* .....4a. */
0xe2, 0x74, 0x5a, 0xd0, 0x16, 0x8f, 0x30, 0x63, /* .tZ...0c */
0x34, 0x9a, 0xdd, 0x49, 0x5c, 0x16, 0x0f, 0x2c, /* 4..I\.., */
0xab, 0xd6, 0x04, 0x79, 0xf4, 0xdb, 0xe4, 0xd7, /* ...y.... */
0x3c, 0x22                                      /* <" */
};

/* Frame (74 bytes) */
static uint8_t icmp_frame[74] = {
0x08, 0x00, 0x27, 0xae, 0x3e, 0xd3, 0x08, 0x00, /* ..'.>... */
0x27, 0x00, 0xa8, 0x1e, 0x08, 0x00, 0x45, 0x00, /* '.....E. */
0x00, 0x3c, 0x00, 0x95, 0x00, 0x00, 0x80, 0x01, /* .<...... */
0x48, 0x10, 0xc0, 0xa8, 0x38, 0x65, 0xc0, 0xa8, /* H...8e.. */
0x38, 0x66, 0x08, 0x00, 0x4d, 0x1e, 0x00, 0x01, /* 8f..M... */
0x00, 0x3d, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* .=abcdef */
0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
0x68, 0x69                                      /* hi */
};

/* Frame (42 bytes) */
static uint8_t arp_frame[42] = {
0x08, 0x00, 0x27, 0xae, 0x3e, 0xd3, 0x08, 0x00, /* ..'.>... */
0x27, 0x00, 0xa8, 0x1e, 0x08, 0x06, 0x00, 0x01, /* '....... */
0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x08, 0x00, /* ........ */
0x27, 0x00, 0xa8, 0x1e, 0xc0, 0xa8, 0x38, 0x65, /* '.....8e */
0x08, 0x00, 0x27, 0xae, 0x3e, 0xd3, 0xc0, 0xa8, /* ..'.>... */
0x38, 0x66                                      /* 8f */
};

/* Frame (98 bytes) */
static uint8_t ip6udp_frame[98] = {
0x33, 0x33, 0x00, 0x00, 0x00, 0xfb, 0x00, 0x22, /* 33....." */
0x68, 0x0f, 0xba, 0x87, 0x86, 0xdd, 0x60, 0x00, /* h.....`. */
0x00, 0x00, 0x00, 0x2c, 0x11, 0xff, 0xfe, 0x80, /* ...,.... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x22, /* ......." */
0x68, 0xff, 0xfe, 0x0f, 0xba, 0x87, 0xff, 0x02, /* h....... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x14, 0xe9, /* ........ */
0x14, 0xe9, 0x00, 0x2c, 0x48, 0x45, 0x00, 0x00, /* ...,HE.. */
0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x07, 0x5f, 0x70, 0x6c, 0x61, 0x73, /* ..._plas */
0x6d, 0x61, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, /* ma._tcp. */
0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, /* local... */
0x00, 0x01                                      /* .. */
};

/* Frame (78 bytes) */
static uint8_t icmp6_frame[78] = {
0x33, 0x33, 0xff, 0x50, 0x54, 0xd7, 0xd0, 0x67, /* 33.PT..g */
0xe5, 0x30, 0x06, 0xad, 0x86, 0xdd, 0x60, 0x00, /* .0....`. */
0x00, 0x00, 0x00, 0x18, 0x3a, 0xff, 0x00, 0x00, /* ....:... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, /* ........ */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
0x00, 0x01, 0xff, 0x50, 0x54, 0xd7, 0x87, 0x00, /* ...PT... */
0x54, 0x6c, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80, /* Tl...... */
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x1b, /* ........ */
0xdd, 0x4f, 0xdb, 0x50, 0x54, 0xd7              /* .O.PT. */
};

#endif /* __TEST_RAW_FRAMES_H__ */
