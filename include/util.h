#ifndef VNCPWD_UTIL_H
#define VNCPWD_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define VNC_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

int         vnc_str_ieq(const char *a, const char *b);
int         vnc_str_istarts(const char *hay, const char *prefix);
int         vnc_str_iends(const char *hay, const char *suffix);
const char *vnc_str_icontains(const char *hay, const char *needle);
void        vnc_trim(char *s);
int         vnc_copy(char *dst, size_t cap, const char *src);
void        vnc_utf8_bom_strip(const char **data, size_t *len);
int         vnc_expand_path(const char *in, char *out, size_t outcap);
int         vnc_file_exists(const char *path);
int         vnc_is_tty(FILE *f);
size_t      vnc_read_file(const char *path, char **out, size_t max_bytes);

/* Enumerate regular files in dir whose name ends with suffix (case-insensitive),
 * NULL meaning "any".  cb receives the full path.  Returns files visited. */
typedef int (*vnc_dir_cb)(void *ctx, const char *path);
int vnc_list_dir(const char *dir, const char *suffix, vnc_dir_cb cb, void *ctx);

/* Produce a redacted rendering of a secret.  When show is 0 only the first
 * character and the length are kept. */
void vnc_mask_secret(const char *secret, size_t len, int show, char *out, size_t outcap);
/* Escape control and non-ASCII bytes so output stays on one line. */
void vnc_escape(const char *in, size_t len, char *out, size_t outcap);

#endif /* VNCPWD_UTIL_H */
