#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <time.h>
#include <unistd.h>
#include <termios.h>

#include <sodium.h>

static void require(int ok, const char *msg) {
    if (!ok) {
        fprintf(stderr, "%s\n", msg);
        abort();
    }
}

static void TIMER_INIT(struct timespec *ts) {
    require(!clock_gettime(CLOCK_THREAD_CPUTIME_ID, ts), "time");
}

static int64_t tv_diff_ns(struct timespec *t1, struct timespec *t0);

static void TIMER_FINALIZE(
        struct timespec *t0, struct timespec *t1,
        const char *msg) {
    require(!clock_gettime(CLOCK_THREAD_CPUTIME_ID, t1), "time"); \
    printf("%s: took %ld ns\n", msg, tv_diff_ns(t1, t0));
}

unsigned my_getpass(const char *msg, char *pw, unsigned pw_len) {
    const int stdin_fd = fileno(stdin);

    require(isatty(stdin_fd), "must read password from a tty");

    printf("%s", msg);

    struct termios termios_p_orig;

    require(!tcgetattr(stdin_fd, &termios_p_orig), "tcgetattr");

    struct termios termios_p_noecho;
    require(sizeof termios_p_noecho == sizeof termios_p_orig, "wat");
    memcpy(&termios_p_noecho, &termios_p_orig, sizeof termios_p_orig);

    termios_p_noecho.c_lflag &= ~ECHO;

    require(
            !tcsetattr(stdin_fd, TCSAFLUSH, &termios_p_noecho),
            "tcsetattr noecho");

    require(
            fgets(pw, pw_len, stdin) != NULL,
            "fgets failed to read password");

    // reset the tty before we possibly abort
    require(
            !tcsetattr(stdin_fd, TCSAFLUSH, &termios_p_orig),
            "tcsetattr reset");

    char *newline = index(pw, '\n');

    require(newline != NULL, "pw too long for buffer");

    *newline = '\0';

    return newline - pw;
}

static void print_bytes_hex(unsigned char *x, int len) {
    putchar('0');
    putchar('x');

    for (int i = 0; i < len; i++) {
        printf("%02hhx", x[i]);
    }
}

static int64_t tv_diff_ns(struct timespec *t1, struct timespec *t0) {
    int64_t diff_s = ((int64_t) t1->tv_sec) - t0->tv_sec;

    return diff_s * 1e9 + abs(t1->tv_nsec - t0->tv_nsec);
}

int main(void) {
    require(sodium_init() != -1, "failed to init libsodium");

    printf("init'd\n");

    if (0) {
    int x = 0;

    for (int i = 1 << 20; i; i--) {
        x = (x << 1) ^ randombytes_random();
    }

    printf("got %u\n", x);

    {
        unsigned char hash[crypto_generichash_BYTES];

        crypto_generichash(
                hash, sizeof hash,
                (unsigned char*) &x, sizeof x,
                NULL, 0);

        printf("hashed: ");

        print_bytes_hex(hash, sizeof hash);

        putchar('\n');
    }

    {
        unsigned char shorthash[crypto_shorthash_BYTES];
        unsigned char key[crypto_generichash_KEYBYTES];

        crypto_shorthash_keygen(key);
        crypto_shorthash(shorthash, (unsigned char*) &x, sizeof x, key);

        printf("shorthashed: ");

        print_bytes_hex(shorthash, sizeof shorthash);

        putchar('\n');
    }
    }

    {
        // password

        char hash[crypto_pwhash_STRBYTES];

        char pw[2048];

        my_getpass("enter a password: ", pw, sizeof pw);

        int pw_len = sizeof pw; //strlen(pw);
        //const char pw[] = "my-password-is-very-good";
        //pw_len = sizeof pw;

        struct timespec t0, t1;

        for (unsigned opslimit = 1;
                    opslimit <= crypto_pwhash_OPSLIMIT_SENSITIVE;
                    opslimit++) {
            printf("pw=\"%s\"\n", pw);
            printf("opslimit=%u\n", opslimit);

            TIMER_INIT(&t0);

            require(
                    crypto_pwhash_str(
                        hash, pw, pw_len,
                        opslimit,
                        crypto_pwhash_MEMLIMIT_INTERACTIVE
                        //crypto_pwhash_OPSLIMIT_SENSITIVE,
                        //crypto_pwhash_MEMLIMIT_SENSITIVE
                            ) == 0,
                    "out of mem hashing pw");

            TIMER_FINALIZE(&t0, &t1, "hashing");

            printf("%s\n", hash);

            TIMER_INIT(&t0);

            require(
                    crypto_pwhash_str_verify(
                        hash, pw, pw_len) == 0,
                    "verify failed");

            TIMER_FINALIZE(&t0, &t1, "verify");

            putchar('\n');
        }

        TIMER_INIT(&t0);

        require(
                crypto_pwhash_str(
                    hash, pw, pw_len,
                    crypto_pwhash_OPSLIMIT_SENSITIVE,
                    crypto_pwhash_MEMLIMIT_SENSITIVE
                        ) == 0,
                "out of mem hashing pw");

        TIMER_FINALIZE(&t0, &t1, "high mem hash");

        printf("%s\n", hash);
    }

    return 0;
}
