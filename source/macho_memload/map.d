module macho_memload.map;

import macho_memload.constants;
import macho_memload.parse;
import core.stdc.string : memcpy, memset, strlen;

nothrow @nogc:

struct memload_image
{
    void* base;
    size_t size;
    void* entry;
    int cputype;
    int cpusubtype;
    ulong slide;
    int owns_mapping;
}

private size_t pageAlign(size_t n)
{
    enum page = 4096;
    return (n + page - 1) & ~(page - 1);
}

version (Windows)
{
    extern (Windows) void* VirtualAlloc(void* addr, size_t size, uint type, uint protect);
    extern (Windows) int VirtualFree(void* addr, size_t size, uint type);
    enum MEM_COMMIT = 0x1000;
    enum MEM_RESERVE = 0x2000;
    enum MEM_RELEASE = 0x8000;
    enum PAGE_EXECUTE_READWRITE = 0x40;
}

version (Posix)
{
    extern (C) void* mmap(void* addr, size_t length, int prot, int flags, int fd, long offset);
    extern (C) int munmap(void* addr, size_t length);
    enum PROT_READ = 1;
    enum PROT_WRITE = 2;
    enum PROT_EXEC = 4;
    enum MAP_PRIVATE = 0x02;
    version (linux)
        enum MAP_ANON = 0x20;
    else
        enum MAP_ANON = 0x1000;
    enum MAP_FAILED = cast(void*)-1;
}

version (OSX)
{
    extern (C) void* dlopen(const(char)* file, int mode);
    extern (C) void* dlsym(void* handle, const(char)* name);
    enum RTLD_NOW = 2;
}

void* osMapRWX(size_t size)
{
    version (Windows)
    {
        return VirtualAlloc(null, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    else version (Posix)
    {
        auto p = mmap(null, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED)
            return null;
        return p;
    }
    else
        return null;
}

void osUnmap(void* p, size_t size)
{
    if (p is null)
        return;
    version (Windows)
        VirtualFree(p, 0, MEM_RELEASE);
    else version (Posix)
        munmap(p, size);
}

private int copySegments(const MachoView* view, ubyte* base, ulong slide)
{
    foreach (i; 0 .. view.nsegs)
    {
        const s = view.segs[i];
        if (s.vmsize == 0)
            continue;
        auto dest = base + cast(size_t)((s.vmaddr + slide) - (view.vmMin + slide));
        // dest = base + (vmaddr - vmMin)
        dest = base + cast(size_t)(s.vmaddr - view.vmMin);
        if (s.filesize)
            memcpy(dest, view.bytes + cast(size_t) s.fileoff, cast(size_t) s.filesize);
        if (s.vmsize > s.filesize)
            memset(dest + cast(size_t) s.filesize, 0, cast(size_t)(s.vmsize - s.filesize));
    }
    return MEMLOAD_OK;
}

private ubyte* vmToPtr(const MachoView* view, ubyte* base, ulong vm)
{
    if (vm < view.vmMin || vm >= view.vmMax)
        return null;
    return base + cast(size_t)(vm - view.vmMin);
}

private int applyRebase(const MachoView* view, ubyte* base, ulong slide)
{
    if (!view.dyld.present || view.dyld.rebaseSize == 0)
        return MEMLOAD_OK;
    if (!inRange(view.length, view.dyld.rebaseOff, view.dyld.rebaseSize))
        return MEMLOAD_ERR_RANGE;
    auto p = view.bytes + view.dyld.rebaseOff;
    const len = cast(size_t) view.dyld.rebaseSize;
    size_t i = 0;
    uint segIndex;
    ulong segOff;
    while (i < len)
    {
        const b = p[i++];
        const op = b & REBASE_OPCODE_MASK;
        const imm = b & REBASE_IMMEDIATE_MASK;
        if (op == REBASE_OPCODE_DONE)
            break;
        else if (op == REBASE_OPCODE_SET_TYPE_IMM)
        {
            // pointer type only
        }
        else if (op == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB)
        {
            segIndex = imm;
            ulong v;
            auto rc = readUleb(p, len, &i, &v);
            if (rc != MEMLOAD_OK)
                return rc;
            segOff = v;
        }
        else if (op == REBASE_OPCODE_ADD_ADDR_ULEB)
        {
            ulong v;
            auto rc = readUleb(p, len, &i, &v);
            if (rc != MEMLOAD_OK)
                return rc;
            segOff += v;
        }
        else if (op == REBASE_OPCODE_ADD_ADDR_IMM_SCALED)
            segOff += imm * 8;
        else if (op == REBASE_OPCODE_DO_REBASE_IMM_TIMES
            || op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES
            || op == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
            || op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB)
        {
            ulong times = imm;
            ulong skip;
            if (op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES
                || op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB)
            {
                auto rc = readUleb(p, len, &i, &times);
                if (rc != MEMLOAD_OK)
                    return rc;
            }
            if (op == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB)
                times = 1;
            if (op == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB)
            {
                auto rc = readUleb(p, len, &i, &skip);
                if (rc != MEMLOAD_OK)
                    return rc;
            }
            ulong extra;
            if (op == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB)
            {
                auto rc = readUleb(p, len, &i, &extra);
                if (rc != MEMLOAD_OK)
                    return rc;
            }
            if (segIndex >= view.nsegs)
                return MEMLOAD_ERR_FORMAT;
            foreach (n; 0 .. times)
            {
                const vm = view.segs[segIndex].vmaddr + segOff;
                auto loc = vmToPtr(view, base, vm);
                if (loc is null)
                    return MEMLOAD_ERR_RANGE;
                ulong val;
                memcpy(&val, loc, 8);
                val += slide;
                memcpy(loc, &val, 8);
                segOff += 8 + skip;
            }
            segOff += extra;
        }
        else
            return MEMLOAD_ERR_UNSUPPORTED;
    }
    return MEMLOAD_OK;
}

private void* resolveSymbol(const MachoView* view, int dylibOrd, const(char)* name)
{
    version (OSX)
    {
        if (name is null || name[0] == 0)
            return null;
        // dylib ordinals are 1-based
        if (dylibOrd <= 0 || cast(uint)(dylibOrd - 1) >= view.ndylibs)
            return null;
        auto path = dylibPath(view, cast(uint)(dylibOrd - 1));
        if (path is null)
            return null;
        auto h = dlopen(path, RTLD_NOW);
        if (h is null)
            return null;
        const skipUnderscore = name[0] == '_' ? name + 1 : name;
        auto s = dlsym(h, skipUnderscore);
        if (s is null)
            s = dlsym(h, name);
        return s;
    }
    else
    {
        cast(void) view;
        cast(void) dylibOrd;
        cast(void) name;
        return null;
    }
}

private int applyBind(const MachoView* view, ubyte* base, const(ubyte)* p, size_t len)
{
    if (len == 0)
        return MEMLOAD_OK;
    size_t i = 0;
    int dylibOrd = 1;
    const(char)* sym;
    uint segIndex;
    ulong segOff;
    long addend;
    while (i < len)
    {
        const b = p[i++];
        const op = b & BIND_OPCODE_MASK;
        const imm = b & BIND_IMMEDIATE_MASK;
        if (op == BIND_OPCODE_DONE)
            break;
        else if (op == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM)
            dylibOrd = imm;
        else if (op == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB)
        {
            ulong v;
            auto rc = readUleb(p, len, &i, &v);
            if (rc != MEMLOAD_OK)
                return rc;
            dylibOrd = cast(int) v;
        }
        else if (op == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM)
            dylibOrd = imm ? (cast(int) imm | ~cast(int) BIND_IMMEDIATE_MASK) : 0;
        else if (op == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM)
        {
            sym = cast(const(char)*)(p + i);
            while (i < len && p[i] != 0)
                i++;
            if (i < len)
                i++;
        }
        else if (op == BIND_OPCODE_SET_TYPE_IMM)
        {
        }
        else if (op == BIND_OPCODE_SET_ADDEND_SLEB)
        {
            auto rc = readSleb(p, len, &i, &addend);
            if (rc != MEMLOAD_OK)
                return rc;
        }
        else if (op == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB)
        {
            segIndex = imm;
            ulong v;
            auto rc = readUleb(p, len, &i, &v);
            if (rc != MEMLOAD_OK)
                return rc;
            segOff = v;
        }
        else if (op == BIND_OPCODE_ADD_ADDR_ULEB)
        {
            ulong v;
            auto rc = readUleb(p, len, &i, &v);
            if (rc != MEMLOAD_OK)
                return rc;
            segOff += v;
        }
        else if (op == BIND_OPCODE_DO_BIND
            || op == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
            || op == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
            || op == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB)
        {
            ulong times = 1;
            ulong skip;
            ulong extra;
            if (op == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB)
            {
                auto rc = readUleb(p, len, &i, &times);
                if (rc != MEMLOAD_OK)
                    return rc;
                rc = readUleb(p, len, &i, &skip);
                if (rc != MEMLOAD_OK)
                    return rc;
            }
            if (op == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB)
            {
                auto rc = readUleb(p, len, &i, &extra);
                if (rc != MEMLOAD_OK)
                    return rc;
            }
            if (segIndex >= view.nsegs)
                return MEMLOAD_ERR_FORMAT;
            foreach (n; 0 .. times)
            {
                const vm = view.segs[segIndex].vmaddr + segOff;
                auto loc = vmToPtr(view, base, vm);
                if (loc is null)
                    return MEMLOAD_ERR_RANGE;
                auto resolved = resolveSymbol(view, dylibOrd, sym);
                version (OSX)
                {
                    if (resolved is null)
                        return MEMLOAD_ERR_BIND;
                    ulong val = cast(ulong) resolved + addend;
                    memcpy(loc, &val, 8);
                }
                else
                {
                    // Non-Darwin: leave zeros; callers still get a mapped image for inspection.
                    cast(void) resolved;
                }
                segOff += 8 + skip;
            }
            if (op == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED)
                segOff += imm * 8;
            segOff += extra;
        }
        else
            return MEMLOAD_ERR_UNSUPPORTED;
    }
    return MEMLOAD_OK;
}

int memloadMap(const(ubyte)* bytes, size_t length, int wantCpu, memload_image* img)
{
    if (img is null)
        return MEMLOAD_ERR_ARG;
    *img = memload_image.init;
    MachoView view;
    auto rc = parseMacho(bytes, length, wantCpu, &view);
    if (rc != MEMLOAD_OK)
        return rc;
    if (view.chainedFixups)
        return MEMLOAD_ERR_UNSUPPORTED;

    const span = cast(size_t)(view.vmMax - view.vmMin);
    const mapped = pageAlign(span);
    auto base = cast(ubyte*) osMapRWX(mapped);
    if (base is null)
        return MEMLOAD_ERR_MMAP;
    memset(base, 0, mapped);

    // Prefer mapping at preferred address; fall back to wherever OS put us.
    const slide = cast(ulong) base - view.vmMin;
    rc = copySegments(&view, base, slide);
    if (rc != MEMLOAD_OK)
    {
        osUnmap(base, mapped);
        return rc;
    }
    rc = applyRebase(&view, base, slide);
    if (rc != MEMLOAD_OK)
    {
        osUnmap(base, mapped);
        return rc;
    }
    if (view.dyld.present && view.dyld.bindSize)
    {
        if (!inRange(view.length, view.dyld.bindOff, view.dyld.bindSize))
        {
            osUnmap(base, mapped);
            return MEMLOAD_ERR_RANGE;
        }
        rc = applyBind(&view, base, view.bytes + view.dyld.bindOff, view.dyld.bindSize);
        if (rc != MEMLOAD_OK)
        {
            osUnmap(base, mapped);
            return rc;
        }
    }
    if (view.dyld.present && view.dyld.lazyBindSize)
    {
        if (!inRange(view.length, view.dyld.lazyBindOff, view.dyld.lazyBindSize))
        {
            osUnmap(base, mapped);
            return MEMLOAD_ERR_RANGE;
        }
        rc = applyBind(&view, base, view.bytes + view.dyld.lazyBindOff, view.dyld.lazyBindSize);
        if (rc != MEMLOAD_OK)
        {
            osUnmap(base, mapped);
            return rc;
        }
    }

    img.base = base;
    img.size = mapped;
    img.cputype = view.cputype;
    img.cpusubtype = view.cpusubtype;
    img.slide = slide;
    img.owns_mapping = 1;
    if (view.hasEntryOff)
        img.entry = base + cast(size_t) view.entryOff;
    else if (view.hasEntryVm)
        img.entry = vmToPtr(&view, base, view.entryVm);
    else
        img.entry = base;
    return MEMLOAD_OK;
}

void memloadUnmap(memload_image* img)
{
    if (img is null || img.base is null || !img.owns_mapping)
        return;
    osUnmap(img.base, img.size);
    *img = memload_image.init;
}
