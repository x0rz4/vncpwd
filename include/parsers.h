#ifndef VNCPWD_PARSERS_H
#define VNCPWD_PARSERS_H

#include <stddef.h>

/* ---- INI ------------------------------------------------------------- */

typedef struct {
    void (*on_section)(void *ctx, const char *section);
    void (*on_key)(void *ctx, const char *section, const char *key, const char *value);
} vnc_ini_cb;

int vnc_ini_parse_file(const char *path, const vnc_ini_cb *cb, void *ctx,
                       char *err, size_t errcap);
int vnc_ini_parse_buffer(const char *buf, size_t len, const vnc_ini_cb *cb, void *ctx,
                         char *err, size_t errcap);
/* Section may be NULL for the unnamed/default section.  Returns 0 on success. */
int vnc_ini_get(const char *path, const char *section, const char *key,
                char *out, size_t outcap);

/* ---- VNC connection files (.vnc, Remmina) ---------------------------- */

typedef struct {
    char host[256];
    char port[16];
    char password[512];   /* raw stored value, may be hex or base64 */
    char security[64];
} vnc_connection;

int vnc_connection_parse(const char *path, vnc_connection *conn,
                         char *err, size_t errcap);

#endif /* VNCPWD_PARSERS_H */
