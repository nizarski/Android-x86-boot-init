# Android-x86-boot-init
eval on iso-scan/filename kernel cmdline value, root command injection via a maliciously-named ISO on a Ventoy-style multiboot drive

**Affected:** Android-x86 9.0-r2 (x86_64), `initrd/init` (the boot initrd's main script, EFI boot path)

## Summary
Android-x86's boot `init` script parses `/proc/cmdline` for a token matching `iso-scan/filename=*`, then runs `eval` on a substring of that token with no sanitization, as PID 1, as root, before any part of the Android system is up. The kernel command line reaches this point through `efi/boot/android.cfg`, which builds `iso-scan/filename=$isofile` from a GRUB variable named `isofile` that this ISO's own menus never set, but that Ventoy (the dominant multiboot-USB tool) and compatible tools set to the filename of whatever `.iso` file the user picked from a menu listing files on the drive. A file named with shell metacharacters on a shared Ventoy drive injects a root command the moment someone selects that boot entry.

## Location
- Sink: `initrd/init:158`. `eval \`echo $c | cut -b1-3,18-\``
- Entry point / source: `initrd/init:154-163`, the `for c in \`cat /proc/cmdline\`` loop, matched against `iso-scan/filename=*`

## Taint path
1. `efi/boot/android.cfg:78-80`:
   ```
   if [ -z "$src" -a -n "$isofile" ]; then
       set src=iso-scan/filename=$isofile
   fi
   ```
`$isofile` is never set anywhere in this ISO's own menu tree. It is set by an outer GRUB environment, Ventoy's grub-mode ISO boot being the common case, to the filename of the `.iso` file selected from a multiboot drive's file listing.
2. The same file's `add_entry`/`add_boot_entry` functions pass `$src` straight onto the kernel command line: `linux $kd/kernel root=/dev/ram0 $src $@`. GRUB's own scripting language does not treat backtick, `` $( ) ``, `,`, `&`, or `|` as special characters, so none of them are escaped before the string lands on `/proc/cmdline` byte for byte.
3. `initrd/init:154`, `for c in \`cat /proc/cmdline\``, splits the command line on whitespace only. A token containing any of those metacharacters survives intact as long as the payload itself contains no literal space.
4. `initrd/init:156-158`:
   ```
   iso-scan/filename=*)
       SRC=iso
       eval `echo $c | cut -b1-3,18-`
       ;;
   ```
The `iso-scan/filename=` prefix is exactly 18 bytes. `cut -b1-3,18-` keeps bytes 1-3 (`iso`) and everything from byte 18 onward (the `=` and the attacker-supplied value), producing the literal string `iso=<value>`. `eval` then re-parses that as a full command line. Backtick and `$()` command substitution fire during word expansion regardless of the surrounding `iso=` assignment syntax, so the injected command runs.

FAT32 and exFAT, the usual formats for a Ventoy data partition, forbid only `" * / : < > ? \ |` in filenames. Backtick, `$`, `;`, `&`, `(`, and `)` are all legal characters, so a filename like `` android-x86`touch${IFS}/tmp/pwned`.iso `` is valid on the filesystem.

## Proof of concept
- Method: hand-crafted PoC, exact `init` lines run verbatim under the real shell
- Steps to reproduce (run inside WSL Ubuntu, never on the host):
  1. Write a file standing in for `/proc/cmdline` content:
     ``` BOOT_IMAGE=/kernel root=/dev/ram0 quiet iso-scan/filename=/x`touch${IFS}/tmp/pwned_android_x86`.iso SRC= ```
  2. Run a script containing the exact `init:154-158` loop and `case`/ `eval` lines, copied verbatim, under real `busybox ash` (the actual shell the initrd runs, not bash).
- Trigger input: saved at `~/fcve8/work/poc-001/cmdline.txt`, `run_poc.sh` (WSL Ubuntu).
- Observed effect:
  ```
  === before ===
  ls: /tmp/pwned_android_x86: No such file or directory
  === running exact init:154-158 logic ===
  iso variable is now: /x.iso
  === after ===
  -rw-r--r--    1 x        x                0 Oct  2 17:14 /tmp/pwned_android_x86
  ```
`/tmp/pwned_android_x86` did not exist before the run and exists after, with `$iso` set to `/x.iso`, exactly what `eval iso=/x\`touch${IFS}/tmp/ pwned_android_x86\`.iso` produces: the backtick command runs, its (empty) output gets spliced into the assignment, and `$iso` ends up as the literal text around it.

One real mistake surfaced and got fixed during this test: a first attempt used a payload with a literal space inside the backticks (`touch /tmp/pwned...`). The outer `for c in` loop's whitespace splitting broke that into two separate cmdline tokens before the injection ever reached `eval`, so it silently did nothing. The working payload uses `${IFS}` instead of a literal space, the standard space-avoidance technique for this exact class of bug, which expands to whitespace only after `eval` runs, not before.

## Impact
Anyone who can get one maliciously-named file onto a shared Ventoy (or equivalent) multiboot drive gets root command execution on whoever later boots the Android-x86 entry from that drive, before any part of the Android system, its security policy, or SELinux is active. No GRUB editing, no console access, and no prior compromise of the victim's machine is needed, only a file with a crafted name reaching shared boot media. A standalone, unmodified copy of this ISO booted on its own is not affected: the ISO's own menus never set `$isofile`, and the BIOS/ isolinux.cfg boot path has no `iso-scan`/`isofile` mechanism at all.
