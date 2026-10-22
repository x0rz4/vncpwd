#ifndef VNCPWD_REGISTRY_H
#define VNCPWD_REGISTRY_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    VNC_HIVE_CURRENT_USER = 0,
    VNC_HIVE_LOCAL_MACHINE,
    VNC_HIVE_USERS,
    VNC_HIVE_COUNT
} vnc_hive;

#define VNC_REG_VIEW_DEFAULT 0
#define VNC_REG_VIEW_32      32
#define VNC_REG_VIEW_64      64

/* Registry type codes, mirrored from winnt.h so callers do not need it. */
#define VNC_REG_NONE    0
#define VNC_REG_SZ      1
#define VNC_REG_EXPAND  2
#define VNC_REG_BINARY  3
#define VNC_REG_DWORD   4
#define VNC_REG_MULTI   7

enum {
    VNC_REG_OK = 0,
    VNC_REG_ERR_UNSUPPORTED = -1, /* not Windows, or API unavailable */
    VNC_REG_ERR_NOT_FOUND = -2,
    VNC_REG_ERR_BAD_TYPE = -3,
    VNC_REG_ERR_TOO_SMALL = -4,
    VNC_REG_ERR_FAILED = -5,
};

int vnc_reg_available(void);
const char *vnc_reg_hive_name(vnc_hive hive);

/* Reads a value into out without a terminating NUL; *outlen is the number of
 * bytes written.  type receives VNC_REG_*. */
int vnc_reg_read_value(vnc_hive hive, int view, const char *path, const char *name,
                       uint8_t *out, size_t outcap, size_t *outlen,
                       uint32_t *type, char *err, size_t errcap);

int vnc_reg_read_string(vnc_hive hive, int view, const char *path, const char *name,
                        char *out, size_t outcap, char *err, size_t errcap);

int vnc_reg_read_dword(vnc_hive hive, int view, const char *path, const char *name,
                       uint32_t *out, char *err, size_t errcap);

typedef int (*vnc_reg_visit_fn)(void *ctx, const char *key_path, const char *value_name,
                                uint32_t type, const uint8_t *data, size_t len);

/* Recursively walks root (inclusive).  Returning non-zero from fn stops the
 * walk.  max_depth of 0 visits only root's own values. */
int vnc_reg_walk(vnc_hive hive, int view, const char *root, int max_depth,
                 vnc_reg_visit_fn fn, void *ctx);

#endif /* VNCPWD_REGISTRY_H */
