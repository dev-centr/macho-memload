module min_macho;

import macho_memload;
import core.stdc.stdio : printf;
import core.stdc.stdlib : malloc, free;
import core.stdc.string : memcpy, memset;

nothrow @nogc:

// Minimal 64-bit Mach-O: header + LC_SEGMENT_64 __TEXT + LC_MAIN.
// Enough to prove parse + map without Apple's toolchain.

enum HDR = 32;
enum SEG_CMD = 72; // LC_SEGMENT_64 without sections
enum MAIN_CMD = 24;
enum CMDS = SEG_CMD + MAIN_CMD;
enum TEXT_OFF = HDR + CMDS;
enum TEXT_SZ = 16;
enum FILE_SZ = TEXT_OFF + TEXT_SZ;
enum VMADDR = 0x100000000UL;

extern (C) int main()
{
    auto buf = cast(ubyte*) malloc(FILE_SZ);
    if (buf is null)
        return 2;
    memset(buf, 0, FILE_SZ);

    void w32(size_t o, uint v)
    {
        memcpy(buf + o, &v, 4);
    }

    void w64(size_t o, ulong v)
    {
        memcpy(buf + o, &v, 8);
    }

    w32(0, MH_MAGIC_64);
    w32(4, CPU_TYPE_X86_64);
    w32(8, 3); // ALL
    w32(12, MH_EXECUTE);
    w32(16, 2); // ncmds
    w32(20, CMDS);
    w32(24, 0); // flags
    w32(28, 0);

    // LC_SEGMENT_64 __TEXT
    w32(32, LC_SEGMENT_64);
    w32(36, SEG_CMD);
    memcpy(buf + 40, "__TEXT".ptr, 6);
    w64(56, VMADDR);
    w64(64, 0x1000);
    w64(72, 0);
    w64(80, FILE_SZ);
    w32(88, 7); // maxprot rwx
    w32(92, 5); // initprot rx
    w32(96, 0); // nsects
    w32(100, 0);

    // LC_MAIN — entryoff relative to file start
    w32(32 + SEG_CMD, LC_MAIN);
    w32(32 + SEG_CMD + 4, MAIN_CMD);
    w64(32 + SEG_CMD + 8, TEXT_OFF);
    w64(32 + SEG_CMD + 16, 0);

    // ret
    buf[TEXT_OFF] = 0xc3;

    MachoView view;
    auto rc = parseMacho(buf, FILE_SZ, 0, &view);
    if (rc != MEMLOAD_OK)
    {
        printf("parse failed: %s\n", memload_strerror(rc));
        free(buf);
        return 1;
    }
    if (view.nsegs != 1 || view.cputype != CPU_TYPE_X86_64)
    {
        printf("unexpected parse fields\n");
        free(buf);
        return 1;
    }

    memload_image img;
    rc = memload_map(buf, FILE_SZ, &img);
    if (rc != MEMLOAD_OK)
    {
        printf("map failed: %s\n", memload_strerror(rc));
        free(buf);
        return 1;
    }
    if (img.base is null || img.entry is null)
    {
        printf("null mapping\n");
        memload_unmap(&img);
        free(buf);
        return 1;
    }
    memload_unmap(&img);
    free(buf);
    printf("macho-memload ok\n");
    return 0;
}
