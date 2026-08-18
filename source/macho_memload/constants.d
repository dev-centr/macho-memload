module macho_memload.constants;

nothrow @nogc:

enum uint MH_MAGIC_64 = 0xfeedfacf;
enum uint MH_CIGAM_64 = 0xcffaedfe;
enum uint MH_MAGIC = 0xfeedface;
enum uint FAT_MAGIC = 0xcafebabe;
enum uint FAT_CIGAM = 0xbebafeca;
enum uint FAT_MAGIC_64 = 0xcafebabf;
enum uint FAT_CIGAM_64 = 0xbfbafeca;

enum int CPU_ARCH_ABI64 = 0x01000000;
enum int CPU_TYPE_X86 = 7;
enum int CPU_TYPE_X86_64 = CPU_ARCH_ABI64 | CPU_TYPE_X86;
enum int CPU_TYPE_ARM = 12;
enum int CPU_TYPE_ARM64 = CPU_ARCH_ABI64 | CPU_TYPE_ARM;

enum uint MH_EXECUTE = 0x2;
enum uint MH_DYLIB = 0x6;
enum uint MH_BUNDLE = 0x8;

enum uint LC_REQ_DYLD = 0x80000000;
enum uint LC_SEGMENT = 0x1;
enum uint LC_SYMTAB = 0x2;
enum uint LC_UNIXTHREAD = 0x5;
enum uint LC_DYSYMTAB = 0xb;
enum uint LC_LOAD_DYLIB = 0xc;
enum uint LC_ID_DYLIB = 0xd;
enum uint LC_LOAD_DYLINKER = 0xe;
enum uint LC_SEGMENT_64 = 0x19;
enum uint LC_UUID = 0x1b;
enum uint LC_CODE_SIGNATURE = 0x1d;
enum uint LC_SEGMENT_SPLIT_INFO = 0x1e;
enum uint LC_DYLD_INFO = 0x22;
enum uint LC_DYLD_INFO_ONLY = LC_REQ_DYLD | LC_DYLD_INFO;
enum uint LC_MAIN = LC_REQ_DYLD | 0x28;
enum uint LC_SOURCE_VERSION = 0x2a;
enum uint LC_DYLD_CHAINED_FIXUPS = LC_REQ_DYLD | 0x34;
enum uint LC_DYLD_EXPORTS_TRIE = LC_REQ_DYLD | 0x33;

enum ubyte REBASE_OPCODE_MASK = 0xF0;
enum ubyte REBASE_IMMEDIATE_MASK = 0x0F;
enum ubyte REBASE_OPCODE_DONE = 0x00;
enum ubyte REBASE_OPCODE_SET_TYPE_IMM = 0x10;
enum ubyte REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20;
enum ubyte REBASE_OPCODE_ADD_ADDR_ULEB = 0x30;
enum ubyte REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40;
enum ubyte REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50;
enum ubyte REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60;
enum ubyte REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70;
enum ubyte REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80;

enum ubyte BIND_OPCODE_MASK = 0xF0;
enum ubyte BIND_IMMEDIATE_MASK = 0x0F;
enum ubyte BIND_OPCODE_DONE = 0x00;
enum ubyte BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10;
enum ubyte BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20;
enum ubyte BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30;
enum ubyte BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40;
enum ubyte BIND_OPCODE_SET_TYPE_IMM = 0x50;
enum ubyte BIND_OPCODE_SET_ADDEND_SLEB = 0x60;
enum ubyte BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70;
enum ubyte BIND_OPCODE_ADD_ADDR_ULEB = 0x80;
enum ubyte BIND_OPCODE_DO_BIND = 0x90;
enum ubyte BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0;
enum ubyte BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0;
enum ubyte BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0;

enum int MEMLOAD_OK = 0;
enum int MEMLOAD_ERR_FORMAT = 1;
enum int MEMLOAD_ERR_ARCH = 2;
enum int MEMLOAD_ERR_RANGE = 3;
enum int MEMLOAD_ERR_MMAP = 4;
enum int MEMLOAD_ERR_BIND = 5;
enum int MEMLOAD_ERR_UNSUPPORTED = 6;
enum int MEMLOAD_ERR_ARG = 7;

enum uint MEMLOAD_MAX_COMMANDS = 256;
enum uint MEMLOAD_MAX_SEGMENTS = 32;
enum uint MEMLOAD_MAX_DYLIBS = 64;
enum size_t MEMLOAD_MAX_IMAGE = size_t(1) << 32;
