module macho_memload.parse;

import macho_memload.constants;
import core.stdc.string : memcpy, strlen;

nothrow @nogc:

struct FatArch
{
    int cputype;
    int cpusubtype;
    uint offset;
    uint size;
}

struct Segment64
{
    char[16] segname;
    ulong vmaddr;
    ulong vmsize;
    ulong fileoff;
    ulong filesize;
    int initprot;
    int maxprot;
}

struct DyldInfo
{
    uint rebaseOff;
    uint rebaseSize;
    uint bindOff;
    uint bindSize;
    uint lazyBindOff;
    uint lazyBindSize;
    bool present;
}

struct DylibName
{
    uint nameOffInCmd; // offset of name from start of load command
    uint cmdFileOff;   // file offset of this load command
}

struct MachoView
{
    const(ubyte)* bytes;
    size_t length;
    uint magic;
    bool swapped;
    int cputype;
    int cpusubtype;
    uint filetype;
    uint ncmds;
    uint sizeofcmds;
    uint headerSize;
    uint cmdsOff;
    ulong vmMin;
    ulong vmMax;
    ulong entryOff; // file offset of entry (LC_MAIN) or 0
    ulong entryVm;  // vmaddr of unixthread pc when present
    bool hasEntryOff;
    bool hasEntryVm;
    uint nsegs;
    Segment64[MEMLOAD_MAX_SEGMENTS] segs;
    DyldInfo dyld;
    uint ndylibs;
    DylibName[MEMLOAD_MAX_DYLIBS] dylibs;
    bool chainedFixups;
}

uint bswap32(uint x)
{
    return (x >> 24) | ((x >> 8) & 0x0000ff00) | ((x << 8) & 0x00ff0000) | (x << 24);
}

ulong bswap64(ulong x)
{
    return (cast(ulong) bswap32(cast(uint) x) << 32) | bswap32(cast(uint)(x >> 32));
}

int hostCpuType()
{
    version (X86_64)
        return CPU_TYPE_X86_64;
    else version (AArch64)
        return CPU_TYPE_ARM64;
    else
        return 0;
}

private uint ru32(const(ubyte)* p, bool swapped)
{
    uint v;
    memcpy(&v, p, 4);
    return swapped ? bswap32(v) : v;
}

private ulong ru64(const(ubyte)* p, bool swapped)
{
    ulong v;
    memcpy(&v, p, 8);
    return swapped ? bswap64(v) : v;
}

private int ri32(const(ubyte)* p, bool swapped)
{
    return cast(int) ru32(p, swapped);
}

bool inRange(size_t len, ulong off, ulong n)
{
    if (n > MEMLOAD_MAX_IMAGE)
        return false;
    if (off > len)
        return false;
    return off + n <= len;
}

int selectFatSlice(const(ubyte)* bytes, size_t length, int wantCpu, FatArch* outArch)
{
    if (bytes is null || length < 8 || outArch is null)
        return MEMLOAD_ERR_ARG;
    const magic = ru32(bytes, false);
    bool swapped;
    uint narch;
    uint headerSz = 8;
    bool is64;
    if (magic == FAT_MAGIC)
    {
        swapped = false;
        is64 = false;
    }
    else if (magic == FAT_CIGAM)
    {
        swapped = true;
        is64 = false;
    }
    else if (magic == FAT_MAGIC_64)
    {
        swapped = false;
        is64 = true;
    }
    else if (magic == FAT_CIGAM_64)
    {
        swapped = true;
        is64 = true;
    }
    else
        return MEMLOAD_ERR_FORMAT;

    narch = ru32(bytes + 4, swapped);
    if (narch == 0 || narch > 16)
        return MEMLOAD_ERR_FORMAT;

    const rec = is64 ? 32u : 20u;
    if (!inRange(length, headerSz, cast(ulong) narch * rec))
        return MEMLOAD_ERR_RANGE;

    FatArch fallback;
    bool haveFallback;
    foreach (i; 0 .. narch)
    {
        auto recp = bytes + headerSz + i * rec;
        FatArch a;
        a.cputype = ri32(recp, swapped);
        a.cpusubtype = ri32(recp + 4, swapped);
        if (is64)
        {
            const off = ru64(recp + 8, swapped);
            const sz = ru64(recp + 16, swapped);
            if (off > uint.max || sz > uint.max)
                return MEMLOAD_ERR_RANGE;
            a.offset = cast(uint) off;
            a.size = cast(uint) sz;
        }
        else
        {
            a.offset = ru32(recp + 8, swapped);
            a.size = ru32(recp + 12, swapped);
        }
        if (wantCpu != 0 && a.cputype == wantCpu)
        {
            *outArch = a;
            return MEMLOAD_OK;
        }
        if (!haveFallback)
        {
            fallback = a;
            haveFallback = true;
        }
    }
    if (wantCpu != 0)
        return MEMLOAD_ERR_ARCH;
    if (!haveFallback)
        return MEMLOAD_ERR_ARCH;
    *outArch = fallback;
    return MEMLOAD_OK;
}

int parseMacho(const(ubyte)* bytes, size_t length, int wantCpu, MachoView* view)
{
    if (bytes is null || view is null || length < 32)
        return MEMLOAD_ERR_ARG;
    *view = MachoView.init;
    view.bytes = bytes;
    view.length = length;

    const magic0 = ru32(bytes, false);
    if (magic0 == FAT_MAGIC || magic0 == FAT_CIGAM || magic0 == FAT_MAGIC_64 || magic0 == FAT_CIGAM_64)
    {
        FatArch arch;
        const sel = wantCpu == 0 ? hostCpuType() : wantCpu;
        auto rc = selectFatSlice(bytes, length, sel, &arch);
        if (rc != MEMLOAD_OK)
            return rc;
        if (!inRange(length, arch.offset, arch.size) || arch.size < 32)
            return MEMLOAD_ERR_RANGE;
        return parseThin(bytes + arch.offset, arch.size, view);
    }
    return parseThin(bytes, length, view);
}

int parseThin(const(ubyte)* bytes, size_t length, MachoView* view)
{
    if (length < 32)
        return MEMLOAD_ERR_FORMAT;
    view.bytes = bytes;
    view.length = length;
    const rawMagic = ru32(bytes, false);
    view.magic = rawMagic;
    if (rawMagic == MH_MAGIC_64)
        view.swapped = false;
    else if (rawMagic == MH_CIGAM_64)
        view.swapped = true;
    else if (rawMagic == MH_MAGIC)
        return MEMLOAD_ERR_UNSUPPORTED; // 32-bit Mach-O not mapped
    else
        return MEMLOAD_ERR_FORMAT;

    view.cputype = ri32(bytes + 4, view.swapped);
    view.cpusubtype = ri32(bytes + 8, view.swapped);
    view.filetype = ru32(bytes + 12, view.swapped);
    view.ncmds = ru32(bytes + 16, view.swapped);
    view.sizeofcmds = ru32(bytes + 20, view.swapped);
    view.headerSize = 32;
    view.cmdsOff = 32;

    if (view.ncmds == 0 || view.ncmds > MEMLOAD_MAX_COMMANDS)
        return MEMLOAD_ERR_FORMAT;
    if (!inRange(length, view.cmdsOff, view.sizeofcmds))
        return MEMLOAD_ERR_RANGE;

    view.vmMin = ulong.max;
    view.vmMax = 0;

    size_t off = view.cmdsOff;
    foreach (i; 0 .. view.ncmds)
    {
        if (!inRange(length, off, 8))
            return MEMLOAD_ERR_RANGE;
        const cmd = ru32(bytes + off, view.swapped);
        const cmdsize = ru32(bytes + off + 4, view.swapped);
        if (cmdsize < 8 || !inRange(length, off, cmdsize))
            return MEMLOAD_ERR_RANGE;

        if (cmd == LC_SEGMENT_64)
        {
            if (cmdsize < 72)
                return MEMLOAD_ERR_FORMAT;
            if (view.nsegs >= MEMLOAD_MAX_SEGMENTS)
                return MEMLOAD_ERR_RANGE;
            Segment64 s;
            memcpy(s.segname.ptr, bytes + off + 8, 16);
            s.vmaddr = ru64(bytes + off + 24, view.swapped);
            s.vmsize = ru64(bytes + off + 32, view.swapped);
            s.fileoff = ru64(bytes + off + 40, view.swapped);
            s.filesize = ru64(bytes + off + 48, view.swapped);
            s.maxprot = ri32(bytes + off + 56, view.swapped);
            s.initprot = ri32(bytes + off + 60, view.swapped);
            if (s.filesize && !inRange(length, s.fileoff, s.filesize))
                return MEMLOAD_ERR_RANGE;
            if (s.vmsize)
            {
                if (s.vmaddr < view.vmMin)
                    view.vmMin = s.vmaddr;
                const end = s.vmaddr + s.vmsize;
                if (end > view.vmMax)
                    view.vmMax = end;
            }
            view.segs[view.nsegs] = s;
            view.nsegs++;
        }
        else if (cmd == LC_MAIN)
        {
            if (cmdsize < 24)
                return MEMLOAD_ERR_FORMAT;
            view.entryOff = ru64(bytes + off + 8, view.swapped);
            view.hasEntryOff = true;
        }
        else if (cmd == LC_UNIXTHREAD)
        {
            // flavor + count then GPRs. x86_64 unixthread: rip at offset 16+8*16 from cmd start
            // after cmd+cmdsize+flavor+count = 16, then 21 qwords, rip is the 16th (index 16).
            if (cmdsize >= 16 + 8 * 17)
            {
                // x86_64 thread state: rip at qword index 16
                view.entryVm = ru64(bytes + off + 16 + 16 * 8, view.swapped);
                view.hasEntryVm = true;
            }
        }
        else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY)
        {
            if (cmdsize < 48)
                return MEMLOAD_ERR_FORMAT;
            view.dyld.present = true;
            view.dyld.rebaseOff = ru32(bytes + off + 8, view.swapped);
            view.dyld.rebaseSize = ru32(bytes + off + 12, view.swapped);
            view.dyld.bindOff = ru32(bytes + off + 16, view.swapped);
            view.dyld.bindSize = ru32(bytes + off + 20, view.swapped);
            view.dyld.lazyBindOff = ru32(bytes + off + 32, view.swapped);
            view.dyld.lazyBindSize = ru32(bytes + off + 36, view.swapped);
        }
        else if (cmd == LC_LOAD_DYLIB)
        {
            if (cmdsize < 24)
                return MEMLOAD_ERR_FORMAT;
            if (view.ndylibs >= MEMLOAD_MAX_DYLIBS)
                return MEMLOAD_ERR_RANGE;
            DylibName d;
            d.nameOffInCmd = ru32(bytes + off + 8, view.swapped);
            d.cmdFileOff = cast(uint) off;
            view.dylibs[view.ndylibs] = d;
            view.ndylibs++;
        }
        else if (cmd == LC_DYLD_CHAINED_FIXUPS)
        {
            view.chainedFixups = true;
        }

        off += cmdsize;
    }

    if (view.nsegs == 0 || view.vmMin == ulong.max || view.vmMax <= view.vmMin)
        return MEMLOAD_ERR_FORMAT;
    if (view.vmMax - view.vmMin > MEMLOAD_MAX_IMAGE)
        return MEMLOAD_ERR_RANGE;
    return MEMLOAD_OK;
}

const(char)* dylibPath(const MachoView* view, uint index)
{
    if (view is null || index >= view.ndylibs)
        return null;
    const d = view.dylibs[index];
    const pos = d.cmdFileOff + d.nameOffInCmd;
    if (pos >= view.length)
        return null;
    return cast(const(char)*)(view.bytes + pos);
}

int readUleb(const(ubyte)* p, size_t len, size_t* i, ulong* outVal)
{
    ulong result = 0;
    uint shift = 0;
    while (*i < len)
    {
        const b = p[*i];
        (*i)++;
        result |= (cast(ulong)(b & 0x7f)) << shift;
        if ((b & 0x80) == 0)
        {
            *outVal = result;
            return MEMLOAD_OK;
        }
        shift += 7;
        if (shift >= 64)
            return MEMLOAD_ERR_FORMAT;
    }
    return MEMLOAD_ERR_FORMAT;
}

int readSleb(const(ubyte)* p, size_t len, size_t* i, long* outVal)
{
    ulong result = 0;
    uint shift = 0;
    ubyte b;
    do
    {
        if (*i >= len)
            return MEMLOAD_ERR_FORMAT;
        b = p[*i];
        (*i)++;
        result |= (cast(ulong)(b & 0x7f)) << shift;
        shift += 7;
        if (shift >= 64)
            return MEMLOAD_ERR_FORMAT;
    }
    while (b & 0x80);
    if ((b & 0x40) && shift < 64)
        result |= (~0UL) << shift;
    *outVal = cast(long) result;
    return MEMLOAD_OK;
}
