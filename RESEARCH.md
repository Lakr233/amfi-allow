# How this works, and how it was found

Target: macOS 27.0 (26A428), Apple silicon, arm64e, `vm.cs_system_enforcement = 1`,
SIP with debugging restrictions off.

All addresses below are from that build's dyld shared cache. The tool resolves
everything at runtime and refuses if it cannot; the addresses are here for
people retracing the work, not for the code.

---

## 1. The problem

An ad-hoc signed binary carrying `com.apple.private.*` entitlements is refused
by `amfid`, and the kernel kills it at exec (`SIGKILL`, exit 137).

The established answers rewrite `amfid`'s code:

- debugger-based tools break on `-[AMFIPathValidator_macos validateWithError:]`
  and patch the result register. LLDB's default breakpoint is a *software*
  breakpoint, which writes `BRK` into `amfid`'s `__TEXT`.
- patchers overwrite the `ldrb` that loads `_isValid` in that method's epilogue.

Both leave a private, dirty, unsigned executable page in `amfid`. Where
`vm.cs_system_enforcement` is `1`, the kernel validates that page on the next
fault and kills `amfid`:

```
exception    EXC_BAD_ACCESS, SIGKILL (Code Signature Invalid)
termination  namespace CODESIGNING, code 2, indicator "Invalid Page"
```

The sysctl is read-only at runtime. This was reproduced end to end twice: the
patch is written, reads back correctly, and `amfid` dies anyway. It is not an
implementation problem — that whole family of approaches is closed on such a
host.

## 2. Injecting a dylib is not the way in either

The obvious alternative — load a dylib into `amfid` and swizzle in-process,
touching no `__TEXT` — has to clear three gates:

| gate | status |
| --- | --- |
| remote thread to call `dlopen` | on arm64e, `PC`/`LR` in a thread state must be PAC-signed; an unsigned state needs `com.apple.private.thread-set-state`, one of `debugserver`'s entitlements |
| dyld honouring `DYLD_INSERT_LIBRARIES` | `amfid` is a platform binary with entitlements, so it is restricted and dyld strips `DYLD_*`. Lifting that needs the validator's `_shouldUnrestrict`, which comes from `[AMFIRequirementsManager allowUnsafeDynamicLinking]` — **the same internal-only preference discussed below** |
| an ad-hoc dylib loading into a platform binary | needs library validation globally off, via `DisableLibraryValidation` in `/Library/Preferences/com.apple.security.libraryvalidation.plist` |

So injection is not a prerequisite, it is a *consequence*: the key to the second
gate is the same byte described in §4. And once you have that byte, the
`Entitlements` key already solves the original problem, so no dylib is needed.

Worth noting in passing: third-party arm64e binaries run fine on this build
without `arm64e_preview_abi`. Every probe used in this work was
`clang -arch arm64e` plus an ad-hoc signature.

## 3. Where the decision is actually made

`-[AMFIPathValidator_macos validateWithError:]` (`0x23cea8c68`), on the path for
non-Apple code carrying restricted entitlements:

```
0x23cea8eb4  ldr  x0, [x27, #0xa08]   ; OBJC_CLASS_$_AMFIRequirementsManager
0x23cea8eb8  bl   …                    ; +sharedManager
0x23cea8ec4  bl   …                    ; -restrictedRequirement
0x23cea8ed4  cbz  x23, 0x23cea8fd8     ; nil -> "Restricted requirement not created"
…
             SecStaticCodeCheckValidityWithErrors(self->_code, 6, x23, &err)
```

Whether a binary may carry restricted entitlements comes down to satisfying
`[[AMFIRequirementsManager sharedManager] restrictedRequirement]`.

That requirement is **not** nil at rest. `-init` ends by calling
`-resetRestrictedRequirement` (`0x23cea53c8` → `0x23cea54c4`), which builds:

```
anchor apple or (anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists)
```

Apple-signed, or Mac App Store signed.

> This correction came from the machine, not from reading. The first version of
> the tool assumed nil and prefixed a bare `anchor apple`, which would have
> dropped the Mac App Store clause and been *stricter* than stock for some
> signed apps. `status` printing `set` is what exposed it. The tool now reads
> the stock requirement back from the runtime with `SecRequirementCopyString`
> and only ever appends to it, so its output cannot be narrower than the
> default.

## 4. The preference, and the byte that gates it

`-[AMFIRequirementsManager checkCodeRequirementsPreferenceUnsynchronized]`
(`0x23cea56b8`):

```
0x23cea56b8  ldrb w8, [x0, #0x49]      ; _isRunningInternalBuild
0x23cea56c0  b.ne 0x23cea57ac          ; not internal -> return, file never read
…
             dict = [NSDictionary dictionaryWithContentsOfFile:
                        @"/Library/Preferences/com.apple.security.coderequirements.plist"]
             x21 = dict[@"Entitlements"]
             x22 = dict[@"AllowUnsafeDynamicLinking"]
0x23cea573c  SecRequirementCreateWithString(x21, 0, &req)
0x23cea5754  str  x8, [x19, #0x30]     ; _restrictedRequirement = req
```

`Entitlements` replaces the requirement outright, so `cdhash H"..."` in it is a
per-binary allowlist evaluated by Apple's own code.

The gate is one BOOL, set once in `-init` (`0x23cea5170`):

```
_isRunningInternalBuild = (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0)
```

Note this is a *different* gate from the library-validation preference, which is
read by `amfid` itself and is satisfied on any host with debugging restrictions
off:

| preference | gate |
| --- | --- |
| `libraryvalidation.plist` → `DisableLibraryValidation` | `amfid` `0x1000059d8`: `csr_check(CSR_ALLOW_TASK_FOR_PID) == 0` **or** `csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0` |
| `coderequirements.plist` → `Entitlements` | framework `0x23cea56b8`: `_isRunningInternalBuild`, i.e. `CSR_ALLOW_APPLE_INTERNAL` only |

The clean way to satisfy the second is to set the Apple Internal SIP bit, which
means a trip to recoveryOS. The alternative is to write the byte.

### The trap

```
0x23cea5758  mov  w8, #1
0x23cea576c  strb w8, [x19, #0x48]     ; _allowUnsafeDynamicLinking = 1  (!)
0x23cea5770  cbz  x22, 0x23cea5780
0x23cea577c  strb w0, [x19, #0x48]     ; only an explicit key overrides it
```

**Setting `Entitlements` alone switches `_allowUnsafeDynamicLinking` on.** That
is global: every validator's `_shouldUnrestrict` becomes 1 (`0x23cea93e4`),
processes stop being marked restricted, and `DYLD_INSERT_LIBRARIES` works
system-wide again. The tool therefore always writes
`AllowUnsafeDynamicLinking = false` explicitly; `status` confirms it stays `0`.

## 5. Finding the byte without hardcoding anything

The singleton pointer lives in a static slot in the shared cache, which is
mapped at the same address in every process, `amfid` included:

```
+[AMFIRequirementsManager sharedManager]  0x23cea5038
  0x23cea5094  ldr x8, [x8, #0x560]  ->  0x287f22560   sharedManager.onceToken
  0x23cea50a4  ldr x0, [x8, #0x568]  ->  0x287f22568   sharedManager.manager   <- slot
```

The tool does not hardcode that address. It calls `+sharedManager` in its own
process, decodes the `adrp`/`ldr` pairs in the method, reads each computed
address, and takes the one whose contents equal its own singleton. Three
candidates are produced on this build; exactly one matches. No match is a
refusal, not a guess.

Then:

```
task_for_pid(amfid) -> mach_vm_read_overwrite(slot) -> amfid's singleton P
mach_vm_write(P + ivar_offset("_isRunningInternalBuild"), 1)      <- one byte
```

Ivar offsets come from `class_getInstanceVariable()`. The write is skipped if
the value already matches and verified by reading back. `P` must pass three
checks first: the class bits of its isa match this process's class, both BOOL
ivars read as 0 or 1, and the slot is non-null.

**The target is malloc'd heap**, not the shared cache. No `mach_vm_protect`, no
copy-on-write of a cache page, nothing executable, nothing for the code-signing
monitor to object to. That is the entire difference from patching.

Blast radius: `_isRunningInternalBuild` has four direct readers on this build
(`0x23cea5584`, `0x23cea56b8`, `0x23cea57b0`, `0x23cea5884`), all inside
`AMFIRequirementsManager` and all about this preference. The one external
caller of the getter (`0x23cea6f00`, in the validator's init) uses it to decide
whether to read the sysctl `security.mac.amfi.qa_root_certs_allowed`, which is 0
on a production machine. `amfid` itself never calls it.

## 6. Measurements

Test subject: an ad-hoc signed binary carrying `com.apple.private.virtualization*`,
signed as part of an app bundle. Exit 137 = `SIGKILL`.

| sample | cdhash | signature | stock amfid | allowlist live |
| --- | --- | --- | --- | --- |
| the binary itself | A | valid | **137** | **0** |
| positive control: whole bundle copied to an unrelated `/tmp` path | A | valid | 137 | **0** |
| negative control: same bundle, binary re-signed with the same entitlements | B | valid | 137 | **137** |
| bare copy: binary lifted out of its bundle | A | **invalid** | 137 | 137 |

- The **positive control** matters because path-scoped bypasses exist and would
  produce the same result for the original location. An unrelated path still
  runs, so the criterion really is the cdhash. (Checked at the same time: no
  debugger attached to `amfid`.)
- The **negative control** is the one that proves scope. Same ad-hoc signature,
  same private entitlements, different cdhash — still refused, logged by `amfid`
  as `Adhoc signed app with restricted entitlements detected` and
  `-424 "The file is adhoc signed but contains restricted entitlements"`. This
  is not a switch that lets every ad-hoc binary through.
- The **bare copy** fails for an unrelated and correct reason. A binary signed
  as part of a bundle seals the bundle's `Info.plist` in a special slot; lifted
  out, `codesign -v` itself reports
  `invalid Info.plist (plist or signature have been modified)` (`-67030`) and
  `amfid` reports `-420 "The signature on the file is invalid"`. It dies at
  basic signature validity, before entitlements are considered. **Allowlist
  things in their bundle.**

End to end, with the allowlist live, the subject launched and ran normally —
not just `--help`, but its full workload.

## 7. Rollback, and a caching caveat

After `off` (preference removed, `amfid` restarted):

| | result |
| --- | --- |
| a **fresh** copy, allowlisted cdhash, never validated before | **137 — refused** |
| a copy `amfid` validated while the allowlist was live | 0 — still runs |

The kernel caches AMFI verdicts per vnode, and `off` cannot revoke one already
cached. Policy genuinely returns to stock — new files are refused immediately —
but an already-admitted file keeps running until its vnode is recycled
(rewriting the file, or a reboot). Apart from the preference file, the tool
leaves nothing on disk; the byte lives only in `amfid`'s memory and is gone the
moment it restarts.

## 8. Address appendix (macOS 27.0 / 26A428)

```
AMFIPathValidator_macos
  -validateWithError:                        0x23cea8c68
     fetch restrictedRequirement             0x23cea8eb4 … 0x23cea8ec4
     fetch allowUnsafeDynamicLinking -> +0x35  0x23cea93e4
     epilogue ldrb w19,[x19,#0x31] (_isValid)  0x23cea8e44
  ivars: +0x31 _isValid  +0x32 _areEntitlementsValidated
         +0x33 _isApple  +0x35 _shouldUnrestrict

AMFIRequirementsManager                      0x287f224e8
  +sharedManager                             0x23cea5038
     sharedManager.onceToken                 0x287f22560
     sharedManager.manager  <- slot          0x287f22568
  -init                                      0x23cea5114
     csr_check(0x10) -> _isRunningInternalBuild  0x23cea5170
     calls resetRestrictedRequirement        0x23cea53c8
  -resetRestrictedRequirement                0x23cea54c4
  -checkCodeRequirementsPreferenceUnsynchronized  0x23cea56b8
     implicit _allowUnsafeDynamicLinking = 1 0x23cea5758
     explicit key overrides it               0x23cea577c
  -restrictedRequirement                     0x23cea5558
  ivars: +0x30 _restrictedRequirement
         +0x48 _allowUnsafeDynamicLinking
         +0x49 _isRunningInternalBuild

amfid (/usr/libexec/amfid, __TEXT @ 0x100000000)
  library-validation MIG handler             0x100001b20
     g_libraryValidationDisabled             0x100025198
  preference reload                          0x100005970
     gate: csr_check(4)  != 0 -> 0x100024ba0 0x100005ae8
     gate: csr_check(0x10)== 0 -> 0x1000251a8 0x100005b14
  fsevent handler                            0x100005ab4
```

`launchd` watches both preference paths via `LaunchEvents` /
`com.apple.fsevents.matching` in `com.apple.MobileFileIntegrity.plist`, so
touching the file makes a running `amfid` reload it — no restart needed, and
the log line is `Received configuration fsevent, reloading preferences.`
