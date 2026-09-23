# amfi-allow

Let an ad-hoc signed binary carry Apple-private entitlements on macOS, by cdhash,
without patching a single instruction.

## The problem

A binary that is ad-hoc signed *and* carries `com.apple.private.*` entitlements is
refused by `amfid`, and the kernel kills it at exec. The usual workarounds patch
`amfid`'s code — a debugger breakpoint, or overwriting the `ldrb` in
`-[AMFIPathValidator_macos validateWithError:]`. Both leave a dirty, unsigned
executable page in `amfid`. Where `vm.cs_system_enforcement` is `1`, the kernel
validates that page on the next fault and kills `amfid` outright
(`CODESIGNING` / `"Invalid Page"`). The sysctl is read-only at runtime.

## The approach

AMFI already ships the feature. `-[AMFIRequirementsManager
checkCodeRequirementsPreferenceUnsynchronized]` reads
`/Library/Preferences/com.apple.security.coderequirements.plist` and takes its
`Entitlements` key as the code requirement a binary must satisfy to be allowed
restricted entitlements. Put `cdhash H"..."` in there and you have a per-binary
allowlist, evaluated by Apple's own code.

That preference is gated on one BOOL:

```
_isRunningInternalBuild = (csr_check(CSR_ALLOW_APPLE_INTERNAL) == 0)
```

So `amfi-allow` writes **one byte** — that ivar, in the singleton, on `amfid`'s
heap. Ordinary `rw-` malloc memory: no `mach_vm_protect`, no copy-on-write of a
shared-cache page, nothing executable, nothing for the code-signing monitor to
object to. `vm.cs_system_enforcement` stops mattering.

Nothing is hardcoded. The singleton's slot is found by decoding
`+[AMFIRequirementsManager sharedManager]` and testing each address it loads
against the singleton in this process; ivar offsets come from the live ObjC
runtime; the stock requirement is read back from the runtime and only ever
appended to. If anything fails to resolve, it refuses instead of writing.

## Build

```sh
make
```

`clang` and the macOS SDK, nothing else.

## Use

```sh
sudo ./amfi-allow allow /path/to/your.app/Contents/MacOS/binary
sudo ./amfi-allow status
sudo ./amfi-allow off
```

`allow` computes the binary's cdhashes, appends them to the stock requirement,
writes the preference, sets the byte, and waits for `amfid` to adopt the result.
`--hold N` keeps re-applying for N seconds in case `amfid` restarts. `off`
removes the preference and restarts `amfid`.

## Requirements

- Apple silicon, macOS 26/27 (tested on 27.0 / 26A428)
- root, and SIP with debugging restrictions off (`csrutil enable --without debug`),
  which is also what makes `amfid` honour the preference at all

## Notes

- The byte lives only in `amfid`'s memory. Re-run `allow` after a reboot or any
  `amfid` restart — the preference file persists, the byte does not.
- Allowlist your binary **in its bundle**. A binary signed as part of a bundle
  seals the bundle's `Info.plist`; copied out on its own, its signature no longer
  verifies and it fails before entitlements are ever considered.
- The tool always writes `AllowUnsafeDynamicLinking = false`. Setting
  `Entitlements` alone turns that flag on as a side effect, which unrestricts
  every process on the machine and hands back `DYLD_INSERT_LIBRARIES`.
- The kernel caches AMFI verdicts per vnode, so a binary already allowed keeps
  running after `off` until its vnode is recycled. New files are refused
  immediately.
- Re-signing changes the cdhash, so rebuilding means running `allow` again.

## Research

[`RESEARCH.md`](RESEARCH.md) has the full derivation: why patching `amfid` is
closed on an enforcing host, why dylib injection is a consequence of this rather
than a route to it, the disassembly the mechanism was read out of, the positive
and negative controls, and an address appendix for retracing the work.

## License

MIT
