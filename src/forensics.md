# Forensics

## "Stego" (40)

## Fix File (45)

## Cybersleuth (70)

## "Stego" "2" (80)

## Git the Flag (100)
Recovering a corrupt Git repository is tricky business. In this case, one
must initialize a new repo, copy the objects from the corrupt repo into the
new repo, and then 'fsck' the new repo to recover the dangling commit. The
flag can be found in that dangling commit.

```[/home/user]$ mkdir git_the_flag

[/home/user]$ cd git_the_flag

[/home/user/git_the_flag]$ git init
Initialized empty Git repository in /home/user/git_the_flag/.git/

[/home/user/git_the_flag]$ cd .git

[/home/user/git_the_flag/.git]$ find objects/
objects/
objects/info
objects/pack

[/home/user/git_the_flag/.git]$ tar --strip-components=1 -zxf /home/user/git-flag.tar.gz git-flag.git/objects

[/home/user/git_the_flag/.git]$ find objects/
objects/
objects/1d
objects/1d/fa60b81dc9a12e567023cb407ad1a4ca550e69
objects/4b
objects/4b/825dc642cb6eb9a060e54bf8d69288fbee4904
objects/71
objects/71/1c0ccbc5adc3a1d89ea050cdeac66e097dc3e7
objects/95
objects/95/83fbd010e8a76a9ac1689391c308327ffc483e
objects/b2
objects/b2/30980188dd226da6531c58201edaf452eea65e
objects/info
objects/pack

[/home/user/git_the_flag/.git]$ cd ../

[/home/user/git_the_flag]$ git fsck
notice: HEAD points to an unborn branch (master)
Checking object directories: 100% (256/256), done.
notice: No default references
dangling commit 711c0ccbc5adc3a1d89ea050cdeac66e097dc3e7

[/home/user/git_the_flag/.git]$ git show 711c0ccbc5adc3a1d89ea050cdeac66e097dc3e7
commit 711c0ccbc5adc3a1d89ea050cdeac66e097dc3e7
Author: Michael <zhan4854@umn.edu>
Date:   Thu Nov 29 00:23:36 2018 -0600

    remove flag

diff --git a/flag.txt b/flag.txt
deleted file mode 100644
index b230980..0000000
--- a/flag.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-flag{55d0048163b415843bb9a1ad888cf0d4}
-
```

Thus the flag is 'flag{55d0048163b415843bb9a1ad888cf0d4}'

## Keyboard (140)
