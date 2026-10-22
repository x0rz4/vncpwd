#ifndef VNCPWD_DETECTOR_H
#define VNCPWD_DETECTOR_H

#include <stddef.h>
#include <stdint.h>
#include "encoding.h"
#include "format_validator.h"
#include "registry.h"

#define VNC_DETECT_TEXT_MAX 1024

enum {
    VNC_DETECT_OK = 0,
    VNC_DETECT_ERR_ARG = -1,
    VNC_DETECT_ERR_EMPTY = -2,
    VNC_DETECT_ERR_FORMAT = -3,
    VNC_DETECT_ERR_LENGTH = -4,
};

typedef struct {
    vnc_encoding   encoding;
    uint8_t        cipher[VNC_CIPHERTEXT_MAX];
    size_t         cipher_len;
    vnc_validation validation;
    int            recovered;
    const char    *reason;
} vnc_detection;

/* hint may be VNC_ENC_AUTO (infer from content and reg_type).
 * reg_type is a VNC_REG_* code, or VNC_REG_NONE for non-registry input. */
int vnc_detect_value(const uint8_t *data, size_t len, uint32_t reg_type,
                     vnc_encoding hint, vnc_detection *out);

#endif /* VNCPWD_DETECTOR_H */
