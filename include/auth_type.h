#ifndef VNCPWD_AUTH_TYPE_H
#define VNCPWD_AUTH_TYPE_H

typedef enum {
    VNC_AUTH_UNKNOWN = 0,
    VNC_AUTH_NONE,          /* security type 1 */
    VNC_AUTH_VNC_PASSWORD,  /* security type 2, classic DES challenge */
    VNC_AUTH_VENCRYPT,      /* security type 19, negotiated TLS/plain */
    VNC_AUTH_TLSVNC,        /* VeNCrypt subtype 258 */
    VNC_AUTH_X509VNC,       /* VeNCrypt subtype 260 */
    VNC_AUTH_RA2,           /* TigerVNC RSA-AES */
    VNC_AUTH_RA2_256,       /* TigerVNC RSA-AES-256 */
    VNC_AUTH_MSLOGON,       /* UltraVNC MS-Logon / DSM plugin */
    VNC_AUTH_WINDOWS,       /* OS account (RealVNC/TightVNC/TigerVNC) */
    VNC_AUTH_PAM,           /* x11vnc / libvncserver PAM */
    VNC_AUTH_KERBEROS,
    VNC_AUTH_SSO            /* RealVNC Connect cloud/SSO */
} vnc_auth_type;

typedef enum {
    VNC_RISK_INFO = 0,
    VNC_RISK_LOW,
    VNC_RISK_MEDIUM,
    VNC_RISK_HIGH,
    VNC_RISK_CRITICAL
} vnc_risk;

const char   *vnc_auth_name(vnc_auth_type type);
const char   *vnc_auth_description(vnc_auth_type type);
vnc_auth_type vnc_auth_from_name(const char *name);

/* True only for schemes whose secret can be recovered from local storage. */
int      vnc_auth_locally_recoverable(vnc_auth_type type);
/* Baseline exposure of the scheme, independent of configuration. */
vnc_risk vnc_auth_baseline_risk(vnc_auth_type type);
const char *vnc_risk_name(vnc_risk risk);

#endif /* VNCPWD_AUTH_TYPE_H */
