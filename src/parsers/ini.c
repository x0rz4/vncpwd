#include "parsers.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

/*
 * A deliberately small INI reader.  UltraVNC's ultravnc.ini is the main
 * consumer; it uses [section] headers, key=value pairs, ';' and '#' comments.
 * Windows INI writers may emit CRLF and a UTF-16 BOM, so both are handled.
 */
static int utf16le_to_utf8(const char *in, size_t len, char **out, size_t *outlen) {
    size_t i, o = 0;
    char *buf;

    if (len < 2 || (unsigned char)in[0] != 0xff || (unsigned char)in[1] != 0xfe) {
        return -1;
    }
    buf = (char *)malloc(len + 1);
    if (!buf) return -1;
    for (i = 2; i + 1 < len; i += 2) {
        unsigned int cp = (unsigned int)(unsigned char)in[i] |
                          ((unsigned int)(unsigned char)in[i + 1] << 8);
        if (cp < 0x80) {
            buf[o++] = (char)cp;
        } else {
            /* only the common case is needed: map to '?' beyond Latin-1 */
            buf[o++] = (cp < 0x100) ? (char)cp : '?';
        }
    }
    buf[o] = 0;
    *out = buf;
    *outlen = o;
    return 0;
}

int vnc_ini_parse_buffer(const char *buf, size_t len, const vnc_ini_cb *cb, void *ctx,
                         char *err, size_t errcap) {
    char line[4096];
    char section[256];
    size_t pos = 0;

    if (!buf) return -1;
    section[0] = 0;

    while (pos < len) {
        size_t start = pos, end, llen;
        char *eq, *key, *value;

        while (pos < len && buf[pos] != '\n') pos++;
        end = pos;
        if (pos < len) pos++;

        llen = end - start;
        if (llen >= sizeof(line)) llen = sizeof(line) - 1;
        memcpy(line, buf + start, llen);
        line[llen] = 0;

        vnc_trim(line);
        if (line[0] == 0 || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[') {
            char *close = strchr(line, ']');
            if (!close) continue;
            *close = 0;
            vnc_copy(section, sizeof(section), line + 1);
            vnc_trim(section);
            if (cb && cb->on_section) cb->on_section(ctx, section);
            continue;
        }

        eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        key = line;
        value = eq + 1;
        vnc_trim(key);
        vnc_trim(value);
        if (key[0] == 0) continue;

        /* Strip a single layer of surrounding quotes. */
        {
            size_t vlen = strlen(value);
            if (vlen >= 2 && value[0] == '"' && value[vlen - 1] == '"') {
                value[vlen - 1] = 0;
                value++;
            }
        }

        if (cb && cb->on_key) cb->on_key(ctx, section, key, value);
    }

    if (err && errcap) err[0] = 0;
    return 0;
}

int vnc_ini_parse_file(const char *path, const vnc_ini_cb *cb, void *ctx,
                       char *err, size_t errcap) {
    char *raw = NULL;
    char *decoded = NULL;
    const char *text = NULL;
    size_t len = 0, tlen = 0;
    int rc;

    len = vnc_read_file(path, &raw, 4 * 1024 * 1024);
    if (len == (size_t)-1) {
        if (err && errcap) snprintf(err, errcap, "cannot read %s", path);
        return -1;
    }

    /* decoded owns a UTF-16 conversion when one happened; text is the view
     * that gets parsed and may point past a BOM, so the two must be kept
     * apart for free().  Calling free() on the BOM-stripped pointer was a
     * one-byte-offset invalid free. */
    decoded = raw;
    if (utf16le_to_utf8(raw, len, &decoded, &tlen) != 0) {
        decoded = raw;
        tlen = len;
    }
    text = decoded;
    vnc_utf8_bom_strip((const char **)&text, &tlen);

    rc = vnc_ini_parse_buffer(text, tlen, cb, ctx, err, errcap);
    if (decoded != raw) free(decoded);
    free(raw);
    return rc;
}

typedef struct {
    const char *want_section;
    const char *want_key;
    char       *out;
    size_t      outcap;
    int         found;
} get_ctx;

static void get_on_key(void *vctx, const char *section, const char *key, const char *value) {
    get_ctx *g = (get_ctx *)vctx;
    if (g->found) return;
    if (g->want_section && g->want_section[0]) {
        if (!vnc_str_ieq(section, g->want_section)) return;
    } else {
        if (section[0] != 0) return;
    }
    if (!vnc_str_ieq(key, g->want_key)) return;
    vnc_copy(g->out, g->outcap, value);
    g->found = 1;
}

int vnc_ini_get(const char *path, const char *section, const char *key,
                char *out, size_t outcap) {
    vnc_ini_cb cb;
    get_ctx g;
    char err[256];

    if (!path || !key || !out || outcap == 0) return -1;
    out[0] = 0;
    g.want_section = section;
    g.want_key = key;
    g.out = out;
    g.outcap = outcap;
    g.found = 0;
    cb.on_section = NULL;
    cb.on_key = get_on_key;

    if (vnc_ini_parse_file(path, &cb, &g, err, sizeof(err)) != 0) return -1;
    return g.found ? 0 : -1;
}
