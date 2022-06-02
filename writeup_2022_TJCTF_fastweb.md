# TJCTF 2022: fast-web

TODO:
Participant: Dosenpfand

## TL;DR / Short Summary

A reverse engineering challenge where the authentication of a web application had to be bypassed.

## Task Description

`fast-web` was a reversing challenge at [TJCTF](https://tjctf.org/) 2022. The description was as follows.

> I'm sick of all these JavaScript libraries and bloated Python web frameworks!

There were to resources provided with the challenge: A link to a live instance reachable at [fast-web.tjc.tf](https://fast-web.tjc.tf/) and a downloadable ZIP file [server.zip](https://tjctf-2022.storage.googleapis.com/uploads/38698b07e413907398ac354544cbda528a9877838d17aa40eabd2a84d6e20932/server.zip).

When accessing the live instance we where presented with the following text.

> this site is mega fast
> only "sicer" is allowed to view the [fleg](https://fast-web.tjc.tf/flag.txt)

When subsquently trying to access the linked
[fleg.txt](https://fast-web.tjc.tf/flag.txt) we got a basic HTTP authentication prompt as defined in [RFC 7235](https://datatracker.ietf.org/doc/html/rfc7235). Trying with a random username and password we got the following response back.

> <html>
    <head><title>Document Error: Unauthorized</title></head>
    <body>
        <h2>Access Error: Unauthorized</h2>
    </body>
</html>

From this we got the impression that we "just" needed to bypass this authentication, probably with the username `sicer`, to get the flag.

## Analysis Steps

After extracting `server.zip` we get the following folder structure and files.
```
[4.0K]  ./
├── [4.0K]  app/
│   ├── [4.0K]  files/
│   │   ├── [  25]  flag.txt
│   │   ├── [ 366]  index.html
│   │   └── [ 197]  style.css
│   ├── [ 168]  auth.txt
│   └── [ 105]  route.txt
├── [4.0K]  goahead/
│   └── [152K]  server*
└── [ 144]  Dockerfile
```

The directory `app/files` contains the files served by the web application, of which `flag.txt` is the one of interest to us. Of course the local copy does not contain the real flag.

The file `app/auth.txt` is a configuration file that defines the user of the application. It contains just a single line.

```
user name=sicer password=e8b8c38931ff8b4fbd16398cd5cff1738a8e00df5d879786df5597718652a2437158cbfef965c69f555b1dfc10c73244f2cd4ba9f27f0db5b0c59c41448647a1 roles=flagger
```

We interpret this as a user named `sicer` with the role `flagger` being configured. The password seems to be a hash and its length of 64 bytes suggests the assumption of it being a SHA-512 hash.

The file `app/route.txt` contains additional configuration elements for the application.

```
route uri=/flag.txt auth=basic abilities=flag
route uri=/ handler=file

role name=flagger abilities=flag
```

We assume that this file creates a route serving `app/files/flag.txt` at the URI `/flag.txt`, protecting it with HTTP authentication and only letting users with the role with the ability `flag` access it. Additionally, it assigns the `flag` ability to the role `flagger`.

Summarizing our analysis of `app/auth.txt` and `app/route.txt`: The user `sicer` has the right to access `/flag.txt` and we know its hashed password.

The `goahead/server` file is assumed to be the binary serving the application. It is a 64 bit Linux binary with debug symbols.

```
> file goahead/server
goahead/server: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4b392583066eb803ec74f25ace3c13b3ed616b14, for GNU/Linux 3.2.0, not stripped
```

The `Dockerfile` seems to be a standard Ubuntu 20.04 instance launching the goahead `server` binary with the included configuration.

```
FROM ubuntu:focal-20220113
COPY app ./goahead/server /app/
CMD ["/app/server", "-v", "/app/files/", ":80", "/app/auth.txt", "/app/route.txt"]
```

By opening the `goahead/server` binary in [Ghidra](https://ghidra-sre.org/) and looking at the decompiled `main` function we see multiple functions with the prefix `webs` being called, e.g. ` websSetPasswordStoreVerify`, `websOpen` and `websListen`. After researching these function names we discover that the binary is using [Embedthis GoAhead™](https://www.embedthis.com/goahead/doc/), a web server for embedded environments. This conclusion also matched with the folder name `goahead` where the binary resides.

Judging by its name, we deem the `websSetPasswordStoreVerify` function call as most interesting.

```
uVar4 = websSetPasswordStoreVerify(verifyPassword);
```

 It is declared and [documented](https://www.embedthis.com/goahead/doc/ref/api/goahead.html#group___webs_auth_1gac050abeadb21db4a90197eab284b115b) follows.

```
/**
    Set the password store verify callback
    @param verify WebsVerify callback function
    @ingroup WebsAuth
    @stability Stable
 */
PUBLIC void websSetPasswordStoreVerify(WebsVerify verify);
```

The type `WebsVerify` of its argument ist declared as:

```
/**
    Callback to verify the username and password
    @param wp Webs request object
    @return True if the password is verified
    @ingroup Webs
    @stability Stable
 */
typedef bool (*WebsVerify)(Webs *wp);
```

We `Webs` struct describes a HTTP request and has among others a `password` and `username` member.

```
/**
    GoAhead request structure. This is a per-socket connection structure.
    @defgroup Webs Webs
 */
typedef struct Webs {
    // [...]
    char *password; /**< Authorization password */
    // [...]
    char *username; /**< Authorization username */
    // [...]
} Webs;
```

To summarize these interactions: The `main` functions sets the password verification function via `websSetPasswordStoreVerify` to the function `verifyPassword` function. This function takes a pointer to a `Webs` struct (which contains `username` and `password`) and if it authenticates successfully it returns `TRUE`, otherwise `FALSE`.


By checking `verifyPassword` in Ghidra, we see that among other things it calculates a SHA-512 hash, which confirms our initial assumption of the password being hashed using SHA-512.

```
sha512_hash(pcVar6 + lVar3 + 1,0xfffffffffffffffe - lVar3,acStack88);
```

## Exploitable Issue and Solution

An exploitable issue and, as a result thereof, solution was found by my team mates `chriswe` and `ro`. They invested time to understand the decompiled and dissasembled code of `verifyPassword` and discovered that the hash of the password is incorrectly and insufficiently compared to the reference one.
To correctly validate a password just 4 bytes need to have a specific value: The bytes at index 6 and 7 need to be identical to the ones at index 0 and 1 of the reference password. Additionally bytes 4 and 5 need to be zero so the comparison stops immediately and `verifyPassword` returns `TRUE`. Using the hash of the user `sicer` this condition can be expressed as

```
(output[6] == 0xe8) && (output[7] == 0xb8) && (output[4] == 0) && (output[5] == 0)
```

They wrote a brute force script and found that the hash of `5qZ*Bjjjj` produces a hash fullfilling the criteria.
 `b2dd3bff0000e8b81be221d96b0b4a1420de866f3c0970d682f9122fd23b9311a07244235fbc360de75af0bab16ce6d6734a6277cabfac5140842fcfbc45f3e2`

Using it as a password the flag can be retrieved.

**Flag: `tjctf{g0_ah3ad_and_us3_a_n0rm4l_w3b_serv3r_pls_4b470205e474e398}`**

TODO: better? code of comparison?

## Failed Attempts

One of my failed attempts to solve this challenge consisted of fuzzing `verifyPassword` to find a password that authenticates successfully. It consistedd of two parts: Transforming the executable into a library and writing some glue code that is executed by the fuzzer.

We start by finding the location of `verifyPasssword` in the `server` binary using `readelf`.

```
> readelf -a server | grep verifyPassword
   284: 000000000001454b     0 NOTYPE  GLOBAL DEFAULT   14 verifyPassword
```

We can then write a small Python script that uses the [LIEF](https://lief-project.github.io/) library to export the function and save it as a library.

```
#!/usr/bin/env python3
import lief
in_file = 'server'
elf = lief.parse(in_file)
addr = int('0x1454b', 16)
name = 'verifyPassword'
elf.add_exported_function(addr, name)
elf[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)
elf.write(f'lib{in_file}.so')
```

Then we can use this new library to fuzz it using [libFuzzer](https://llvm.org/docs/LibFuzzer.html).

```
#include "goahead-5.2.0/build/linux-x64-default/inc/goahead.h"
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

typedef bool (*verifyPassword_t)(Webs *wp);
verifyPassword_t verifyPassword;

char name[] = "sicer";
char password[] =
    "e8b8c38931ff8b4fbd16398cd5cff1738a8e00df5d879786df5597718652a2437158cbfef9"
    "65c69f555b1dfc10c73244f2cd4ba9f27f0db5b0c59c41448647a10";
char role[] = "flagger";
Webs w;
WebsUser wu;
void *h;
int inited;

void init() {
  wu.name = name;
  wu.password = password;
  wu.roles = role;
  w.user = &wu;

  h = dlopen("libserver.so", RTLD_LAZY);
  if (h == NULL) {
    printf("dlopen failed\n");
    exit(1);
  }
  verifyPassword = (verifyPassword_t)dlsym(h, "verifyPassword");

  inited = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (!inited) {
    init();
  }

  w.password = Data;
  bool ret = verifyPassword(&w);

  if (ret) {
    raise(SIGSEGV);
  }

  return 0;
}
```

In the initialization function `init` we load the new `libserver.so` library and point the `verifyPassword` function pointer to the one from the library. Additionally, we set the target `username`, `password` and `role` in the `WebsUser wu` struct.

Every fuzz iteration the fuzz `Data` is set as a trial password and `verifyPassword` called with it.
If the password authenticates successfully we cause a segmentation fault to stop the fuzz testing.

The code is compiled and run using the following commands.
```
clang -DUSE_LIBFUZZER -O1 -g -fsanitize=fuzzer fuzz.c -no-pie -o fuzz -ldl
LD_LIBRARY_PATH=. ./fuzz CORPUS -workers=4 -jobs=4
```

TODO: no results, why, slow, ... etc.

## Lessons Learned

TODO: Document what you learned during the competition.
TODO: learn more assembly before trying harder reversing examples.
TODO: Know when fuzzing is a viable approach
TODO: gdb

## References

TODO: List external resources (academic papers, technical blogs, CTF writeups, ...) you used while working on this task.
