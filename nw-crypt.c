/*
 * Contains the NetWare 3.x bindery password / client login encryption in use.
 *
 * Written by Rink Springer <rink@rink.nu>
 * Licensed using Creative Commons CC BY.
 */
// gcc -o nw-crypt nw-crypt.c && ./nw-crypt
#include <stdint.h>
#include <string.h>
#include <stdio.h>

const uint8_t nibble_table[256] = {
    0x7, 0x8, 0x0, 0x8, 0x6, 0x4, 0xE, 0x4,
    0x5, 0xC, 0x1, 0x7, 0xB, 0xF, 0xA, 0x8,
    0xF, 0x8, 0xC, 0xC, 0x9, 0x4, 0x1, 0xE,
    0x4, 0x6, 0x2, 0x4, 0x0, 0xA, 0xB, 0x9,
    0x2, 0xF, 0xB, 0x1, 0xD, 0x2, 0x1, 0x9,
    0x5, 0xE, 0x7, 0x0, 0x0, 0x2, 0x6, 0x6,
    0x0, 0x7, 0x3, 0x8, 0x2, 0x9, 0x3, 0xF,
    0x7, 0xF, 0xC, 0xF, 0x6, 0x4, 0xA, 0x0,
    0x2, 0x3, 0xA, 0xB, 0xD, 0x8, 0x3, 0xA,
    0x1, 0x7, 0xC, 0xF, 0x1, 0x8, 0x9, 0xD,
    0x9, 0x1, 0x9, 0x4, 0xE, 0x4, 0xC, 0x5,
    0x5, 0xC, 0x8, 0xB, 0x2, 0x3, 0x9, 0xE,
    0x7, 0x7, 0x6, 0x9, 0xE, 0xF, 0xC, 0x8,
    0xD, 0x1, 0xA, 0x6, 0xE, 0xD, 0x0, 0x7,
    0x7, 0xA, 0x0, 0x1, 0xF, 0x5, 0x4, 0xB,
    0x7, 0xB, 0xE, 0xC, 0x9, 0x5, 0xD, 0x1,
    0xB, 0xD, 0x1, 0x3, 0x5, 0xD, 0xE, 0x6,
    0x3, 0x0, 0xB, 0xB, 0xF, 0x3, 0x6, 0x4,
    0x9, 0xD, 0xA, 0x3, 0x1, 0x4, 0x9, 0x4,
    0x8, 0x3, 0xB, 0xE, 0x5, 0x0, 0x5, 0x2,
    0xC, 0xB, 0xD, 0x5, 0xD, 0x5, 0xD, 0x2,
    0xD, 0x9, 0xA, 0xC, 0xA, 0x0, 0xB, 0x3,
    0x5, 0x3, 0x6, 0x9, 0x5, 0x1, 0xE, 0xE,
    0x0, 0xE, 0x8, 0x2, 0xD, 0x2, 0x2, 0x0,
    0x4, 0xF, 0x8, 0x5, 0x9, 0x6, 0x8, 0x6,
    0xB, 0xA, 0xB, 0xF, 0x0, 0x7, 0x2, 0x8,
    0xC, 0x7, 0x3, 0xA, 0x1, 0x4, 0x2, 0x5,
    0xF, 0x7, 0xA, 0xC, 0xE, 0x5, 0x9, 0x3,
    0xE, 0x7, 0x1, 0x2, 0xE, 0x1, 0xF, 0x4,
    0xA, 0x6, 0xC, 0x6, 0xF, 0x4, 0x3, 0x0,
    0xC, 0x0, 0x3, 0x6, 0xF, 0x8, 0x7, 0xB,
    0x2, 0xD, 0xC, 0x6, 0xA, 0xA, 0x8, 0xD
};

const uint8_t key_table[32] = {
    0x48, 0x93, 0x46, 0x67, 0x98, 0x3D, 0xE6, 0x8D,
    0xB7, 0x10, 0x7A, 0x26, 0x5A, 0xB9, 0xB1, 0x35,
    0x6B, 0x0F, 0xD5, 0x70, 0xAE, 0xFB, 0xAD, 0x11,
    0xF4, 0x47, 0xDC, 0xA7, 0xEC, 0xCF, 0x50, 0xC0
};

// Also known as shuffle()
void nw_hash(const uint8_t* salt /* 4 bytes */, const uint8_t* in /* 32 bytes */, uint8_t* out /* 16 bytes */)
{
    // Apply salt to input data
    uint8_t temp[32];
    for (int n = 0; n < 32; ++n) {
        temp[n] = in[n] ^ salt[n & 3];
    }

    // Two rounds
    uint8_t last = 0;
    for (int round = 0; round < 2; ++round) {
        for(int index = 0; index < 32; ++index) {
            const uint8_t v = temp[(last + index) & 0x1f] - key_table[index];
            const uint8_t new_value = (temp[index] + last) ^ v;
            last += new_value;
            temp[index] = new_value;
        }
    }

    // Combine 32 bytes to 16 by using every byte as nibble
    for (unsigned int index = 0; index < 16; ++index) {
        out[index] =
            nibble_table[temp[index * 2 + 0]] |
            nibble_table[temp[index * 2 + 1]] << 4;
    }
}

// Expands input to 32 bytes
void stretch_input(const uint8_t* in, int in_len, uint8_t* out /* 32 bytes */)
{
    // Determine input length - it is zero-padded at the end so we need to
    // avoid those
    while(in_len > 0 && in[in_len - 1] == 0)
        --in_len;

    // If the input exceeds 32 bytes, XOR the first blocks of 32 bytes
    // into the output
    memset(out, 0, 32);
    while (in_len > 32) {
        for (int n = 0; n < 32; ++n) {
            out[n] = out[n] ^ *in;
            ++in;
        }
        in_len -= 32;
    }

    int in_pos = 0;
    for (int n = 0; n < 32; ++n) {
      if (in_pos == in_len) {
        out[n] = out[n] ^ key_table[n];
        in_pos = 0;
      } else {
        out[n] = out[n] ^ in[in_pos];
        ++in_pos;
      }
    }
}

void nw_encrypt(const uint8_t* key /* 8 bytes */, const uint8_t* in  /* 16 bytes */,uint8_t* out /* 8 bytes */)
{
    // Expand input to 32 bytes
    uint8_t expanded_in[32];
    stretch_input(in, 16, expanded_in);

    // Shuffle with the key to obtain 32 bytes
    uint8_t temp[32];
    nw_hash(&key[0], expanded_in, &temp[0]);
    nw_hash(&key[4], expanded_in, &temp[16]);

    // out[n] = temp[n] ^ temp[31 - n] ^ temp[15 - n] ^ temp[16 + n]
    out[0] = temp[0] ^ temp[31] ^ temp[15] ^ temp[16];
    out[1] = temp[1] ^ temp[30] ^ temp[14] ^ temp[17];
    out[2] = temp[2] ^ temp[29] ^ temp[13] ^ temp[18];
    out[3] = temp[3] ^ temp[28] ^ temp[12] ^ temp[19];
    out[4] = temp[4] ^ temp[27] ^ temp[11] ^ temp[20];
    out[5] = temp[5] ^ temp[26] ^ temp[10] ^ temp[21];
    out[6] = temp[6] ^ temp[25] ^ temp[ 9] ^ temp[22];
    out[7] = temp[7] ^ temp[24] ^ temp[ 8] ^ temp[23];
}

void hash_object_password(uint32_t object_id, const char* pwd, uint8_t* out /* 16 bytes */)
{
    uint8_t key[4];
    key[0] = (object_id >> 24) & 0xff;
    key[1] = (object_id >> 16) & 0xff;
    key[2] = (object_id >>  8) & 0xff;
    key[3] = object_id & 0xff;

    uint8_t expanded_in[32];
    stretch_input(pwd, strlen(pwd), expanded_in);
    nw_hash(key, expanded_in, out);
}

void set_password(uint32_t object_id, const char* pwd, uint8_t* out /* 16 bytes */)
{
    hash_object_password(object_id, pwd, out);
}

void determine_client_login_hash(uint32_t object_id, const uint8_t* key, const char* pwd, uint8_t* out /* 8 bytes */)
{
    uint8_t password_hash[16];
    hash_object_password(object_id, pwd, password_hash);
    nw_encrypt(key, password_hash, out);
}

void determine_server_login_hash(const uint8_t* key, const uint8_t* bindery_pwd, uint8_t* out /* 8 bytes */)
{
    nw_encrypt(key, bindery_pwd, out);
}

int main()
{
    const uint32_t object_id = 0x5000026;

    const uint8_t bindery_pwd_HELLO123[16] = { 0xa3, 0xc2, 0xa1, 0x66, 0x47, 0x6a, 0x77, 0x4d, 0x52, 0xed, 0xba, 0x3d, 0xd1, 0x97, 0x4b, 0x56 };
    uint8_t out_set_pwd[16];
    set_password(object_id, "HELLO123", out_set_pwd);
    printf("set_password(\"HELLO123\") %s\n", memcmp(out_set_pwd, bindery_pwd_HELLO123, 16) == 0 ? "ok" : "failure");

    const uint8_t bindery_pwd_HORSE[16] = { 0x74, 0x57, 0x7f, 0x98, 0x07, 0x90, 0x06, 0xf3, 0x53, 0x9a, 0x8e, 0x94, 0xeb, 0xde, 0xe9, 0x19 };
    set_password(object_id, "HORSE BATTERY STABLE NETWARE", out_set_pwd);
    printf("set_password(\"HORSE...\") %s\n", memcmp(out_set_pwd, bindery_pwd_HORSE, 16) == 0 ? "ok" : "failure");

    const uint8_t login_key1[8] = { 0x3f, 0xb1, 0x7e, 0x62, 0xfc, 0x11, 0xf8, 0x6f };
    uint8_t client_login_hash[8] = {};
    determine_client_login_hash(object_id, login_key1, "HORSE BATTERY STABLE NETWARE", client_login_hash);
    uint8_t server_login_hash[8] = {};
    determine_server_login_hash(login_key1, bindery_pwd_HORSE, server_login_hash);
    printf("login(\"HORSE...\") %s\n", memcmp(client_login_hash, server_login_hash, 8) == 0 ? "ok" : "failure");
}