/* fastcore.c -- compiled hot paths for PythonX v1.1.
   Build: cc -O2 -shared -fPIC fastcore.c -o libpxfast.so
   Everything here is a pure function over byte buffers; the Python
   side keeps all the judgment, this file only does the counting. */

void px_counts(const unsigned char *s, int n, int *letters, int *stats) {
    /* letters[26]: case-insensitive letter counts.
       stats[0]=printable count, stats[1]=space count. */
    int i;
    for (i = 0; i < 26; i++) letters[i] = 0;
    stats[0] = 0; stats[1] = 0;
    for (i = 0; i < n; i++) {
        unsigned char c = s[i];
        if (c >= 'a' && c <= 'z') letters[c - 'a']++;
        else if (c >= 'A' && c <= 'Z') letters[c - 'A']++;
        if (c == 32 || c == 9 || c == 10 || c == 13 || (c >= 33 && c < 127)) stats[0]++;
        if (c == 32) stats[1]++;
    }
}

void px_xor_all_counts(const unsigned char *s, int n, int *out) {
    /* out[key*27 + i]: counts of (s XOR key) for every key 0..255, in
       ONE pass -- the 256-key histogram PythonX ranks XOR keys with.
       Bins 0..25 are letters (case-insensitive), bin 26 is the space
       character, matching PythonX's 27-symbol frequency table. */
    int k, i;
    for (k = 0; k < 256 * 27; k++) out[k] = 0;
    for (k = 0; k < 256; k++) {
        int *row = out + k * 27;
        for (i = 0; i < n; i++) {
            unsigned char c = (unsigned char)(s[i] ^ k);
            if (c >= 'a' && c <= 'z') row[c - 'a']++;
            else if (c >= 'A' && c <= 'Z') row[c - 'A']++;
            else if (c == 32) row[26]++;
        }
    }
}

int px_letters(const unsigned char *s, int n, unsigned char *out) {
    /* Writes the uppercase letters-only stream of s into out; returns length. */
    int i, m = 0;
    for (i = 0; i < n; i++) {
        unsigned char c = s[i];
        if (c >= 'a' && c <= 'z') out[m++] = (unsigned char)(c - 'a' + 'A');
        else if (c >= 'A' && c <= 'Z') out[m++] = c;
    }
    return m;
}

int px_razor(const unsigned char *s, int n, int *keys_out) {
    /* The charset razor, in C: every XOR key whose output lands at
       least 98% inside the base64 alphabet or the hex alphabet.
       Only the true key over encoded text passes; the scan is one
       pass per key over the data, far too slow in pure Python to
       run inside the scorer. Returns the number of keys found. */
    unsigned char is_b64[256], is_hex[256];
    int k, i, found = 0;
    for (i = 0; i < 256; i++) { is_b64[i] = 0; is_hex[i] = 0; }
    for (i = 'A'; i <= 'Z'; i++) is_b64[i] = 1;
    for (i = 'a'; i <= 'z'; i++) is_b64[i] = 1;
    for (i = '0'; i <= '9'; i++) { is_b64[i] = 1; is_hex[i] = 1; }
    is_b64['+'] = 1; is_b64['/'] = 1; is_b64['='] = 1;
    for (i = 'a'; i <= 'f'; i++) is_hex[i] = 1;
    for (i = 'A'; i <= 'F'; i++) is_hex[i] = 1;
    for (k = 1; k < 256; k++) {
        int cb = 0, ch = 0;
        for (i = 0; i < n; i++) {
            unsigned char c = (unsigned char)(s[i] ^ k);
            cb += is_b64[c];
            ch += is_hex[c];
        }
        if ((cb * 100 >= 98 * n) || (ch * 100 >= 98 * n)) keys_out[found++] = k;
    }
    return found;
}

void px_xor(const unsigned char *s, int n, unsigned char key, unsigned char *out) {
    int i;
    for (i = 0; i < n; i++) out[i] = (unsigned char)(s[i] ^ key);
}
