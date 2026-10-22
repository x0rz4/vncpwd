#include "parsers.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

/*
 * .vnc connection files come in two flavours:
 *
 *   RealVNC / TigerVNC / UltraVNC:
 *     [Connection]
 *     Host=example:5900
 *     Password=1fa2...            (hex, 8 or 16 bytes)
 *
 *   Remmina:
 *     [remmina]
 *     server=example:5900
 *     password=<base64 of the hex string>
 *     protocol=VNC
 *
 * The Password field in RealVNC files is the same fixed-key DES blob as the
 * server-side registry value, so it is recoverable with the classic path.
 */

typedef struct {
    vnc_connection *conn;
} conn_ctx;

static void split_host_port(const char *value, vnc_connection *conn) {
    const char *colon;
    size_t n;

    if (!value) return;
    colon = strrchr(value, ':');
    if (!colon) {
        vnc_copy(conn->host, sizeof(conn->host), value);
        return;
    }
    n = (size_t)(colon - value);
    if (n >= sizeof(conn->host)) n = sizeof(conn->host) - 1;
    memcpy(conn->host, value, n);
    conn->host[n] = 0;
    vnc_copy(conn->port, sizeof(conn->port), colon + 1);
}

static void conn_on_key(void *vctx, const char *section, const char *key, const char *value) {
    conn_ctx *c = (conn_ctx *)vctx;
    (void)section;

    if (vnc_str_ieq(key, "host") || vnc_str_ieq(key, "server") ||
        vnc_str_ieq(key, "hostname")) {
        split_host_port(value, c->conn);
    } else if (vnc_str_ieq(key, "port")) {
        vnc_copy(c->conn->port, sizeof(c->conn->port), value);
    } else if (vnc_str_ieq(key, "password")) {
        vnc_copy(c->conn->password, sizeof(c->conn->password), value);
    } else if (vnc_str_ieq(key, "security") ||
               vnc_str_ieq(key, "securitytypes") ||
               vnc_str_ieq(key, "protocol")) {
        vnc_copy(c->conn->security, sizeof(c->conn->security), value);
    }
}

int vnc_connection_parse(const char *path, vnc_connection *conn,
                         char *err, size_t errcap) {
    vnc_ini_cb cb;
    conn_ctx ctx;

    if (!path || !conn) return -1;
    memset(conn, 0, sizeof(*conn));
    ctx.conn = conn;
    cb.on_section = NULL;
    cb.on_key = conn_on_key;

    if (vnc_ini_parse_file(path, &cb, &ctx, err, errcap) != 0) return -1;
    return 0;
}
