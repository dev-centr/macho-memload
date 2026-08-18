module macho_memload.capi;

import macho_memload.constants;
import macho_memload.parse;
import macho_memload.map;

extern (C) nothrow @nogc:

alias memload_image = macho_memload.map.memload_image;

int memload_parse(const(void)* bytes, size_t length, int want_cpu)
{
    MachoView view;
    return parseMacho(cast(const(ubyte)*) bytes, length, want_cpu, &view);
}

int memload_map(const(void)* bytes, size_t length, memload_image* img)
{
    return memloadMap(cast(const(ubyte)*) bytes, length, 0, img);
}

int memload_map_cpu(const(void)* bytes, size_t length, int want_cpu, memload_image* img)
{
    return memloadMap(cast(const(ubyte)*) bytes, length, want_cpu, img);
}

void memload_unmap(memload_image* img)
{
    memloadUnmap(img);
}

const(char)* memload_strerror(int err)
{
    switch (err)
    {
    case MEMLOAD_OK:
        return "ok";
    case MEMLOAD_ERR_FORMAT:
        return "not a Mach-O image";
    case MEMLOAD_ERR_ARCH:
        return "no matching architecture slice";
    case MEMLOAD_ERR_RANGE:
        return "truncated Mach-O";
    case MEMLOAD_ERR_MMAP:
        return "could not map executable memory";
    case MEMLOAD_ERR_BIND:
        return "dyld bind failed";
    case MEMLOAD_ERR_UNSUPPORTED:
        return "unsupported Mach-O feature (chained fixups or 32-bit)";
    case MEMLOAD_ERR_ARG:
        return "invalid argument";
    default:
        return "unknown memload error";
    }
}
