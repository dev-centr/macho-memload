# macho-memload — agent notes

- D **BetterC** library: parse fat/thin Mach-O, map segments, apply classic `dyld_info` rebase/bind.
- Public C ABI in `macho_memload.capi` (`memload_*`).
- Full Apple dyld (chained fixups, interposing, code signing, TCR) is **not** claimed. Experimental.
- No GC. No Phobos in library code.
- Consumers: `dev-centr/binary-tailor` (path/`../macho-memload` in the hive).
