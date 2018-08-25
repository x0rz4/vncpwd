/*
    Copyright 2006 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "d3des.h"      // all the stuff from the VNC public source

#ifdef WIN32
    #include <windows.h>
#else
    #define stricmp strcasecmp
    #define stristr strcasestr
#endif



#define VER     "0.2"
#define BUFFSZ  4096
#define KEYPATH "Software\\ORL"


#ifdef WIN32
int regkey(HKEY hKey, LPCTSTR lpSubKey, LPTSTR lpValueName, uint8_t *buff, int len);
int enum_key(HKEY hkey, uint8_t *reg_path);
int enum_value(HKEY hkey, uint8_t *reg_path);
#endif
void vncpwd(uint8_t *pwd, int bytelen);



int main(int argc, char *argv[]) {
    FILE    *fd;
    int     i,
            n,
            len;
    uint8_t buff[BUFFSZ + 1],
            *arg,
            *p,
            *l;


    setbuf(stdout, NULL);

    fputs("\n"
        "*VNC password decoder "VER"\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stdout);

    if(argc < 2) {
        printf("\n"
            "Usage: %s <file.VNC/password>\n"
            "\n"
            "Works with any VNC application which uses the original VNC encryption, like\n"
            "RealVNC, TightVNC, Ultr@VNC and so on\n"
            "You can pass both the file.vnc or directly an encrypted password (hex too).\n"
#ifdef WIN32
            "Passwords in the registry are automatically showed below if no argument passed:\n"
#endif
            "\n", argv[0]);
#ifdef WIN32
        enum_key(HKEY_CURRENT_USER,  KEYPATH);
        enum_key(HKEY_USERS,         KEYPATH);
        enum_key(HKEY_LOCAL_MACHINE, KEYPATH);
#endif
        goto quit;
    }

    arg = argv[1];

    fd = fopen(arg, "rb");
    if(!fd) {
        p = arg;
        len = strlen(p);

        if(len < 8) {
            printf("- your input password seems in hex format (or shorter than 8 chars)\n");
            p = malloc(argc);
            for(i = 1; i < argc; i++) {
                sscanf(argv[i], "%x", &n);
                p[i - 1] = n;
            }
            len = i - 1;
        } else if(len > 8) {
            printf("- your input password seems in hex format (or longer than 8 chars)\n");
            for(i = 0; ; i++) {
                if(sscanf(arg + (i * 2), "%02x", &n) != 1) break;
                p[i] = n;
            }
            len = i;
        } else {
            printf("- your input password seems in raw format\n");
        }

        vncpwd(p, len);
        printf("\n  Password:   %.*s\n", len, p);
        goto quit;
    }

    while(fgets(buff, sizeof(buff), fd)) {
        for(l = buff; *l && (*l != '\r') && (*l != '\n'); l++);
        *l = 0;

        l = strchr(buff, '=');
        if(!l) continue;
        *l = 0;

        p = buff;
        while(*p && (*p > ' ')) p++;        // skip possible spaces
        *p = 0;

        p = l + 1;
        while(*p && (*p <= ' ')) p++;       // skip possible spaces

        if(!stricmp(buff, "host")) {
            printf("  Hostname    %s\n", p);

        } else if(!stricmp(buff, "port")) {
            printf("  Port        %s\n", p);

        } else if(!stricmp(buff, "password")) {
            vncpwd(p, -1);
            printf("  Password:   %s\n", p);
        }
    }

    fclose(fd);

quit:
    printf("\n  Press RETURN to exit\n");
    fgetc(stdin);
    return(0);
}



#ifdef WIN32

int regkey(HKEY hKey, LPCTSTR lpSubKey, LPTSTR lpValueName, uint8_t *buff, int len) {
    HKEY    key;

    buff[0] = 0;

    if(RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return(-1);
    }
    if(RegQueryValueEx(key, lpValueName, NULL, NULL, buff, (void *)&len) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return(-1);
    }
    RegCloseKey(key);


    /* CODE ADDED FOR VNCPWD */
    if(stristr(lpValueName, "pass") && (len >= 8)) {
        vncpwd(buff, len);
        printf("%-*s   %.*s\n",
            40 - printf("  %s", lpSubKey), lpValueName,
            len, buff);
    }
    /* END */

    return(0);
}



int enum_key(HKEY hkey, uint8_t *reg_path) {
    HKEY    key;
    uint8_t buff[BUFFSZ + 1],
            *p;
    int     len,
            plen,
            k = 0;

    if(RegOpenKeyEx(hkey, reg_path, 0, KEY_READ, &key)) {
        return(-1);
    }

    plen = snprintf(
        buff,
        BUFFSZ,
        "%s\\",
        reg_path);
    if((plen < 0) || (plen >= BUFFSZ)) {
        return(-1);
    }

    enum_value(hkey, buff);

    p = buff + plen;

    for(;;) {
        len = BUFFSZ - plen;
        if(RegEnumKeyEx(
            key,
            k++,
            p,
            (void *)&len,
            NULL,
            NULL,
            NULL,
            NULL)) break;

        enum_key(hkey, buff);
    }

    RegCloseKey(key);
    return(0);
}



int enum_value(HKEY hkey, uint8_t *reg_path) {
    HKEY    key;
    uint8_t buff[BUFFSZ + 1],
            value[BUFFSZ + 1];
    int     len,
            k = 0;

    if(RegOpenKeyEx(hkey, reg_path, 0, KEY_READ, &key)) {
        return(-1);
    }

    for(;;) {
        len = BUFFSZ;
        if(RegEnumValue(
            key,
            k++,
            buff,
            (void *)&len,
            NULL,
            NULL,
            NULL,
            NULL)) break;

        regkey(hkey, reg_path, buff, value, sizeof(value));
    }

    RegCloseKey(key);
    return(0);
}

#endif



void vncpwd(uint8_t *pwd, int bytelen) {     // if bytelen is -1 it's a hex string
    int     len,
            tmp;
    uint8_t fixedkey[8] = { 23,82,107,6,35,78,88,7 },
            *p,
            *o;

    if(bytelen >= 0) {
        o = pwd + bytelen;
    } else {
        for(p = o = pwd; *p; p += 2, o++) {
            sscanf(p, "%02x", &tmp);
            *o = tmp;
        }
    }

    len = o - pwd;
    tmp = len % 8;
    len /= 8;
    if(tmp) len++;

    deskey(fixedkey, DE1);
    for(p = pwd; len--; p += 8) {   // that's wrong since des supports only 8 bytes
        des(p, p);                  // but you know me... I'm crazy
    }

    *o = 0;
}



