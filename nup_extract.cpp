// nup_extract - extract and pack .nup files. Drag a .nup onto the .exe to extract it,
// or drag a folder onto it to create <folder>_packed.nup.
// Format: https://github.com/a55uka/nup (SPEC.md)
//
// Extract: nup_extract.exe file.nup [file2.nup ...] [-o out_folder] [--no-verify]
//   Without -o, extracts into a folder named after the .nup, next to it.
//   Output layout (same as used by `nup pack`):
//     <out>/base/{exefs,romfs}
//     <out>/updates/<decimal version>/{exefs,romfs}
//     <out>/dlc/<title id hex>/<index>/{exefs,romfs}
// Pack:    nup_extract.exe folder [--level N] [--title-id HEX] [--name N] [--publisher P]
//            [--display-version V] [--keep-listings] [--icon path]
//            [--lang-name ja=Name] [--lang-icon ja=path]
//   Without --name the title is the folder name; icon.jpg/png in the folder is used as icon.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <zstd.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// ---------------------------------------------------------------- structures
#pragma pack(push, 1)
struct Superblock {
    uint8_t magic[4];
    uint16_t header_size, header_version;
    uint64_t toc_offset, toc_size;
    uint8_t toc_sha256[32];
    uint64_t blob_offset, file_size;
    uint32_t package_count, flags;
    uint8_t uuid[16], reserved[32];
};
struct TocHeader {
    uint32_t magic, package_count;
    uint64_t dir_count, file_count, string_pool_off, string_pool_size, reserved;
};
struct Package {
    uint64_t title_id;
    uint32_t root_dir, exefs_dir, romfs_dir, version;
    uint8_t kind, flags;
    uint16_t reserved;
    uint32_t reserved2;
    uint64_t meta_offset;
    uint32_t meta_size;
    uint8_t reserved3[20];
};
struct Dir {
    uint32_t name_off, name_len, first_child, child_count;
    uint64_t reserved;
};
struct File {
    uint32_t name_off, name_len;
    uint64_t size, extent_offset, extent_size;
    uint8_t sha256[32];
    uint8_t codec, codec_flags;
    uint16_t reserved2;
    uint8_t reserved3[12];
};
#pragma pack(pop)
static_assert(sizeof(Superblock) == 0x80, "superblock");
static_assert(sizeof(TocHeader) == 0x30, "toc");
static_assert(sizeof(Package) == 0x40, "package");
static_assert(sizeof(Dir) == 0x18, "dir");
static_assert(sizeof(File) == 0x50, "file");

// ---------------------------------------------------------------- SHA-256
struct Sha256 {
    // Shared provider: opening it per file is very expensive.
    static BCRYPT_ALG_HANDLE& prov() {
        static BCRYPT_ALG_HANDLE a = [] {
            BCRYPT_ALG_HANDLE x = nullptr;
            if (BCryptOpenAlgorithmProvider(&x, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) x = nullptr;
            return x;
        }();
        return a;
    }
    static DWORD objlen() {
        static DWORD n = [] {
            DWORD v = 0, got = 0;
            if (prov()) BCryptGetProperty(prov(), BCRYPT_OBJECT_LENGTH, (PUCHAR)&v, sizeof v, &got, 0);
            return v;
        }();
        return n;
    }
    BCRYPT_HASH_HANDLE h = nullptr;
    std::vector<uint8_t> obj;
    bool ok = false;
    Sha256() {
        if (!prov()) return;
        obj.resize(objlen());
        ok = BCryptCreateHash(prov(), &h, obj.data(), (ULONG)obj.size(), nullptr, 0, 0) >= 0;
    }
    ~Sha256() {
        if (h) BCryptDestroyHash(h);
    }
    void update(const void* p, size_t n) {
        if (ok) BCryptHashData(h, (PUCHAR)p, (ULONG)n, 0);
    }
    void finish(uint8_t out[32]) {
        if (ok) BCryptFinishHash(h, out, 32, 0);
    }
};

// ---------------------------------------------------------------- reader
struct Reader {
    std::ifstream in;
    fs::path path;
    std::vector<std::pair<const struct File*, fs::path>> tasks;
    Superblock sb{};
    std::vector<uint8_t> toc;
    const TocHeader* th = nullptr;
    const Package* pk = nullptr;
    const Dir* dirs = nullptr;
    const File* files = nullptr;
    const uint32_t* children = nullptr;
    size_t child_slots = 0;
    const uint8_t* pool = nullptr;
    uint64_t fsize = 0;
    bool verify = true;

    uint64_t files_total = 0;
    std::atomic<uint64_t> files_done{0}, bytes_done{0};
    std::atomic<unsigned> warnings{0};
};

static std::string err;
static std::mutex err_mu, out_mu;
static bool fail(const std::string& m) {
    std::lock_guard<std::mutex> lk(err_mu);
    if (err.empty()) err = m;
    return false;
}

static bool open_nup(Reader& r, const fs::path& path) {
    r.path = path;
    r.in.open(path, std::ios::binary);
    if (!r.in) return fail("could not open file");
    r.in.seekg(0, std::ios::end);
    r.fsize = (uint64_t)r.in.tellg();
    r.in.seekg(0);
    if (r.fsize < sizeof(Superblock)) return fail("file too small");
    r.in.read((char*)&r.sb, sizeof r.sb);
    const Superblock& s = r.sb;
    if (memcmp(s.magic, "NUP", 3) != 0 || s.magic[3] != 1) return fail("not a v1 .nup (invalid magic)");
    if (s.header_size < 0x80) return fail("invalid header_size");
    if (s.flags != 0) return fail("unknown superblock flags");
    if (s.toc_offset != s.header_size) return fail("invalid toc_offset");
    if (s.toc_offset > r.fsize || s.toc_size > r.fsize - s.toc_offset) return fail("TOC out of range");
    if (s.blob_offset < s.toc_offset + s.toc_size || s.blob_offset > r.fsize) return fail("invalid blob_offset");
    if (s.file_size != r.fsize) return fail("file_size mismatch (truncated file?)");
    if (s.package_count < 1) return fail("no packages");

    r.toc.resize((size_t)s.toc_size);
    r.in.seekg((std::streamoff)s.toc_offset);
    r.in.read((char*)r.toc.data(), (std::streamsize)s.toc_size);
    if (!r.in) return fail("error reading the TOC");

    Sha256 sh;
    uint8_t d[32] = {};
    sh.update(r.toc.data(), r.toc.size());
    sh.finish(d);
    if (sh.ok && memcmp(d, s.toc_sha256, 32) != 0) return fail("TOC SHA-256 mismatch (corrupt file)");

    if (r.toc.size() < sizeof(TocHeader)) return fail("TOC too small");
    r.th = (const TocHeader*)r.toc.data();
    const TocHeader& t = *r.th;
    if (memcmp(&t.magic, "TOC\x01", 4) != 0) return fail("invalid TOC magic");
    if (t.package_count != s.package_count) return fail("package_count mismatch");

    uint64_t off = sizeof(TocHeader);
    uint64_t sz = r.toc.size();
    auto fits = [&](uint64_t count, uint64_t each) {
        return count <= (sz - std::min(sz, off)) / each;
    };
    if (!fits(t.package_count, sizeof(Package))) return fail("truncated TOC (packages)");
    r.pk = (const Package*)(r.toc.data() + off);
    off += (uint64_t)t.package_count * sizeof(Package);
    if (!fits(t.dir_count, sizeof(Dir))) return fail("truncated TOC (directories)");
    r.dirs = (const Dir*)(r.toc.data() + off);
    off += t.dir_count * sizeof(Dir);
    if (!fits(t.file_count, sizeof(File))) return fail("truncated TOC (files)");
    r.files = (const File*)(r.toc.data() + off);
    off += t.file_count * sizeof(File);
    if (t.string_pool_off > sz || t.string_pool_size > sz - t.string_pool_off ||
        t.string_pool_off < off)
        return fail("string pool out of range");
    r.children = (const uint32_t*)(r.toc.data() + off);
    r.child_slots = (size_t)((t.string_pool_off - off) / 4);
    r.pool = r.toc.data() + t.string_pool_off;
    return true;
}

static std::string node_name(const Reader& r, uint32_t off, uint32_t len) {
    if ((uint64_t)off + len > r.th->string_pool_size) return {};
    return std::string((const char*)r.pool + off, len);
}

static fs::path u8path(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return fs::path(w);
}

static std::string to_u8(const std::wstring& w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

static bool safe_name(const std::string& n) {
    if (n.empty() || n == "." || n == "..") return false;
    for (char c : n)
        if (c == '/' || c == '\\' || c == ':' || c == '\0' || c == '*' || c == '?' || c == '"' ||
            c == '<' || c == '>' || c == '|')
            return false;
    return true;
}

// Extracts one file; returns false on a fatal (I/O) error.
struct Worker {
    std::ifstream in;
    std::vector<char> ibuf = std::vector<char>(4 << 20);
    std::vector<char> obuf = std::vector<char>(1 << 20);
    ZSTD_DCtx* dctx = ZSTD_createDCtx();
    ~Worker() { ZSTD_freeDCtx(dctx); }
};

static bool extract_file(Reader& r, Worker& w, const File& f, const fs::path& dest) {
    std::ofstream out(dest, std::ios::binary | std::ios::trunc);
    if (!out) return fail("could not create " + to_u8(dest.wstring()));

    Sha256 sh;
    uint64_t written = 0;
    if (f.size == 0) {
        // nothing to do
    } else {
        if (f.extent_offset < r.sb.blob_offset || f.extent_offset > r.fsize ||
            f.extent_size > r.fsize - f.extent_offset)
            return fail("extent out of range in " + to_u8(dest.filename().wstring()));
        w.in.clear();
        w.in.seekg((std::streamoff)f.extent_offset);
        constexpr size_t CH = 4 << 20;
        std::vector<char>& ibuf = w.ibuf;
        if (f.codec == 0) {
            if (f.extent_size != f.size) return fail("raw extent with inconsistent size");
            uint64_t left = f.size;
            while (left) {
                size_t n = (size_t)std::min<uint64_t>(left, CH);
                w.in.read(ibuf.data(), (std::streamsize)n);
                if (!w.in) return fail("truncated read");
                out.write(ibuf.data(), (std::streamsize)n);
                sh.update(ibuf.data(), n);
                written += n;
                left -= n;
            }
        } else if (f.codec == 1) {
            ZSTD_DCtx* dctx = w.dctx;
            std::vector<char>& obuf = w.obuf;
            ZSTD_DCtx_reset(dctx, ZSTD_reset_session_only);
            uint64_t left = f.extent_size;
            size_t ret = 1;
            while (left) {
                size_t n = (size_t)std::min<uint64_t>(left, CH);
                w.in.read(ibuf.data(), (std::streamsize)n);
                if (!w.in) { return fail("truncated read"); }
                left -= n;
                ZSTD_inBuffer ib{ibuf.data(), n, 0};
                while (ib.pos < ib.size) {
                    ZSTD_outBuffer ob{obuf.data(), obuf.size(), 0};
                    ret = ZSTD_decompressStream(dctx, &ob, &ib);
                    if (ZSTD_isError(ret)) {
                        std::string m = ZSTD_getErrorName(ret);
                        return fail("error zstd: " + m);
                    }
                    out.write(obuf.data(), (std::streamsize)ob.pos);
                    sh.update(obuf.data(), ob.pos);
                    written += ob.pos;
                }
            }
            if (ret != 0) return fail("incomplete zstd frame");
        } else {
            return fail("unknown codec " + std::to_string(f.codec));
        }
    }
    out.close();
    if (!out) return fail("write error (disk full?)");
    if (written != f.size) return fail("decompressed size mismatch");
    if (r.verify && sh.ok) {
        uint8_t d[32];
        sh.finish(d);
        if (memcmp(d, f.sha256, 32) != 0) {
            ++r.warnings;
            std::lock_guard<std::mutex> lk(out_mu);
            printf("\n  [!] SHA-256 mismatch: %s\n", to_u8(dest.wstring()).c_str());
        }
    }
    r.bytes_done += written;
    return true;
}

static void progress(Reader& r, bool force = false) {
    static ULONGLONG last = 0;
    ULONGLONG now = GetTickCount64();
    if (!force && now - last < 200) return;
    last = now;
    unsigned pct = r.files_total ? (unsigned)(r.files_done.load() * 100 / r.files_total) : 100;
    std::lock_guard<std::mutex> lk(out_mu);
    printf("\r  %llu/%llu files (%u%%)  %.1f MiB   ", (unsigned long long)r.files_done.load(),
            (unsigned long long)r.files_total, pct, r.bytes_done.load() / 1048576.0);
    fflush(stdout);
}

static bool collect_dir(Reader& r, uint32_t di, const fs::path& dest, int depth) {
    if (depth > 256) return fail("directory tree too deep");
    if (di >= r.th->dir_count) return fail("invalid directory index");
    const Dir& d = r.dirs[di];
    if ((uint64_t)d.first_child + d.child_count > r.child_slots) return fail("invalid children range");
    std::error_code ec;
    fs::create_directories(dest, ec);
    if (ec) return fail("could not create directory " + to_u8(dest.wstring()));
    for (uint32_t i = 0; i < d.child_count; ++i) {
        uint32_t id = r.children[d.first_child + i];
        if (id < r.th->dir_count) {
            const Dir& c = r.dirs[id];
            std::string n = node_name(r, c.name_off, c.name_len);
            if (!safe_name(n)) { ++r.warnings; continue; }
            if (!collect_dir(r, id, dest / u8path(n), depth + 1)) return false;
        } else {
            uint64_t fi = id - r.th->dir_count;
            if (fi >= r.th->file_count) return fail("invalid file index");
            const File& f = r.files[fi];
            std::string n = node_name(r, f.name_off, f.name_len);
            if (!safe_name(n)) { ++r.warnings; continue; }
            r.tasks.emplace_back(&f, dest / u8path(n));
        }
    }
    return true;
}

// Collects the tree (creates directories) and extracts the files using several threads.
static bool extract_dir(Reader& r, uint32_t di, const fs::path& dest, int depth) {
    r.tasks.clear();
    if (!collect_dir(r, di, dest, depth)) return false;
    unsigned nt = std::thread::hardware_concurrency();
    if (nt == 0) nt = 4;
    nt = std::min<unsigned>(nt, 16);
    nt = (unsigned)std::min<size_t>(nt, std::max<size_t>(1, r.tasks.size()));
    std::atomic<size_t> next{0};
    std::atomic<bool> stop{false};
    std::atomic<unsigned> running{nt};
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < nt; ++t)
        pool.emplace_back([&] {
            Worker w;
            w.in.open(r.path, std::ios::binary);
            if (!w.in) { fail("could not reopen the .nup"); stop = true; }
            while (!stop) {
                size_t i = next++;
                if (i >= r.tasks.size()) break;
                if (!extract_file(r, w, *r.tasks[i].first, r.tasks[i].second)) { stop = true; break; }
                ++r.files_done;
            }
            --running;
        });
    while (running > 0) {
        progress(r);
        Sleep(50);
    }
    for (auto& th : pool) th.join();
    return !stop;
}

static uint64_t count_files(const Reader& r, uint32_t di, int depth) {
    if (depth > 256 || di >= r.th->dir_count) return 0;
    const Dir& d = r.dirs[di];
    if ((uint64_t)d.first_child + d.child_count > r.child_slots) return 0;
    uint64_t n = 0;
    for (uint32_t i = 0; i < d.child_count; ++i) {
        uint32_t id = r.children[d.first_child + i];
        n += id < r.th->dir_count ? count_files(r, id, depth + 1) : 1;
    }
    return n;
}

static const char* kind_name(uint8_t k) {
    switch (k) {
        case 0: return "base";
        case 1: return "update";
        case 2: return "addon";
        case 3: return "addon_update";
        case 4: return "system";
        default: return "?";
    }
}

static bool extract_nup(const fs::path& nup, fs::path outdir, bool verify) {
    Reader r;
    r.verify = verify;
    if (!open_nup(r, nup)) return false;

    if (outdir.empty()) outdir = nup.parent_path() / nup.stem();
    if (fs::exists(outdir) && !fs::is_empty(outdir))
        printf("Warning: folder already exists, files will be overwritten: %s\n", to_u8(outdir.wstring()).c_str());

    for (uint32_t i = 0; i < r.th->package_count; ++i)
        if (r.pk[i].kind >= 5) return fail("unknown package kind");

    // Total file count
    for (uint32_t i = 0; i < r.th->package_count; ++i) r.files_total += count_files(r, r.pk[i].root_dir, 0);

    std::map<std::string, int> addon_idx;
    for (uint32_t i = 0; i < r.th->package_count; ++i) {
        const Package& p = r.pk[i];
        char tid[17];
        snprintf(tid, sizeof tid, "%016llx", (unsigned long long)p.title_id);
        fs::path sub;
        switch (p.kind) {
            case 0: sub = "base"; break;
            case 1: sub = fs::path("updates") / std::to_string(p.version); break;
            case 2:
            case 3: sub = fs::path("dlc") / tid / std::to_string(addon_idx[tid]++); break;
            default: sub = fs::path("other") / (std::string(tid) + "_" + std::to_string(i)); break;
        }
        printf("[%u/%u] %s  title=%s  version=%u\n", i + 1, r.th->package_count, kind_name(p.kind), tid,
               p.version);
        if (!extract_dir(r, p.root_dir, outdir / sub, 0)) {
            printf("\n");
            return false;
        }
        progress(r, true);
        printf("\n");
    }
    printf("Done: %llu files -> %s\n", (unsigned long long)r.files_done, to_u8(outdir.wstring()).c_str());
    if (r.warnings) printf("Warnings: %u (hash mismatches or skipped names)\n", r.warnings.load());
    return true;
}

// ====================================================================== PACK
namespace pk {

constexpr uint32_t FILE_TAG = 0x80000000u;
constexpr uint64_t BIG_FILE = 64ull << 20;     // above this: compressed in streaming mode on the main thread
constexpr uint64_t MEM_BUDGET = 1024ull << 20; // approx. memory in flight for the compression threads

struct Options {
    int level = 3;
    bool keep_listings = false;
    bool has_title = false;
    uint64_t title_id = 0;
    std::string name, publisher, display_version;
    fs::path icon;                                 // default-language icon
    std::map<std::string, std::string> lang_names; // tag -> name (UTF-8)
    std::map<std::string, fs::path> lang_icons;    // tag -> image path
};

struct FileObj {
    std::string name;
    fs::path src;
    uint64_t size = 0, eoff = 0, esize = 0;
    uint8_t sha[32] = {};
    uint8_t codec = 0;
};
struct DirObj {
    std::string name;
    std::vector<std::pair<DirObj*, FileObj*>> kids;
    uint32_t id = 0, first = 0, count = 0;
};

struct Ent {
    std::string name;
    fs::path path;
    bool dir;
};

static std::vector<Ent> list_dir(const fs::path& d) {
    std::vector<Ent> v;
    for (auto& e : fs::directory_iterator(d)) {
        std::error_code ec;
        bool isd = e.is_directory(ec);
        v.push_back({to_u8(e.path().filename().wstring()), e.path(), isd});
    }
    std::sort(v.begin(), v.end(), [](const Ent& a, const Ent& b) { return a.name < b.name; });
    return v;
}

struct Tree {
    std::deque<DirObj> dstore;
    std::deque<FileObj> fstore;
    std::vector<DirObj*> dirs;
    std::vector<FileObj*> files;
    std::vector<uint32_t> children;
    bool keep_listings = false;

    DirObj* walk(const fs::path& src, const std::string& name) {
        dstore.emplace_back();
        DirObj* node = &dstore.back();
        node->name = name;
        for (auto& e : list_dir(src)) {
            if (e.dir) {
                node->kids.push_back({walk(e.path, e.name), nullptr});
            } else if (keep_listings || e.name != ".listing") {
                fstore.emplace_back();
                FileObj* f = &fstore.back();
                f->name = e.name;
                f->src = e.path;
                node->kids.push_back({nullptr, f});
            }
        }
        return node;
    }
    uint32_t rec(DirObj* d) {
        uint32_t did = (uint32_t)dirs.size();
        d->id = did;
        dirs.push_back(d);
        size_t base = children.size();
        children.resize(base + d->kids.size());
        for (size_t i = 0; i < d->kids.size(); ++i)
            if (d->kids[i].second) {
                children[base + i] = FILE_TAG + (uint32_t)files.size();
                files.push_back(d->kids[i].second);
            }
        for (size_t i = 0; i < d->kids.size(); ++i)
            if (d->kids[i].first) children[base + i] = rec(d->kids[i].first);
        d->first = (uint32_t)base;
        d->count = (uint32_t)d->kids.size();
        return did;
    }
};

// ---------------------------------------------------------------- discovery
struct PI {
    uint8_t kind = 0;
    fs::path src;
    uint64_t title_id = 0;
    uint32_t version = 0;
    uint8_t flags = 0;
    std::string npdm;
    bool has_build = false;
    uint8_t build[32] = {};
};

static bool slurp(const fs::path& p, std::string& out, size_t maxn = (size_t)-1) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    uint64_t n = (uint64_t)f.tellg();
    f.seekg(0);
    n = std::min<uint64_t>(n, maxn);
    out.resize((size_t)n);
    f.read(out.data(), (std::streamsize)n);
    return (bool)f || f.gcount() == (std::streamsize)n;
}

static void resolve_ids(PI& p, bool override_id, uint64_t ov) {
    for (const char* c : {"exefs/main.npdm", "main.npdm"}) {
        fs::path q = p.src / c;
        std::error_code ec;
        if (fs::is_regular_file(q, ec)) {
            slurp(q, p.npdm);
            size_t off = p.npdm.find("ACI0");
            if (off != std::string::npos && off + 0x18 <= p.npdm.size()) {
                uint64_t id;
                memcpy(&id, p.npdm.data() + off + 0x10, 8);
                if (id) p.title_id = id;
            }
            break;
        }
    }
    for (const char* c : {"exefs/main", "main"}) {
        fs::path q = p.src / c;
        std::error_code ec;
        if (fs::is_regular_file(q, ec)) {
            std::string head;
            slurp(q, head, 0x60);
            if (head.size() == 0x60 && (head.compare(0, 4, "NSO0") == 0 || head.compare(0x10, 4, "NRO0") == 0)) {
                memcpy(p.build, head.data() + 0x40, 32);
                p.has_build = true;
            }
            break;
        }
    }
    if (override_id) p.title_id = ov;
}

static bool dir_exists(const fs::path& p) {
    std::error_code ec;
    return fs::is_directory(p, ec);
}
static bool has_files(const fs::path& d) {
    std::error_code ec;
    for (fs::recursive_directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec)) {
        std::error_code e2;
        if (it->is_regular_file(e2) && it->path().filename() != ".listing") return true;
    }
    return false;
}
static bool all_digits(const std::string& s) {
    if (s.empty() || s.size() > 10) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    return true;
}
static bool is_hex16(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s) if (!isxdigit((unsigned char)c)) return false;
    return true;
}

static void collect_updates(const fs::path& upd, uint64_t base_tid, uint8_t flags, std::vector<PI>& out) {
    for (auto& e : list_dir(upd)) {
        if (!e.dir || !all_digits(e.name) || !has_files(e.path)) continue;
        unsigned long long v = std::stoull(e.name);
        if (v > 0xFFFFFFFFull) continue;
        PI p;
        p.kind = 1;
        p.src = e.path;
        p.version = (uint32_t)v;
        p.flags = flags;
        resolve_ids(p, false, 0);
        if (p.title_id == 0) p.title_id = base_tid;
        out.push_back(std::move(p));
    }
}
static void collect_dlcs(const fs::path& dlc, std::vector<PI>& out) {
    for (auto& t : list_dir(dlc)) {
        if (!t.dir || !is_hex16(t.name)) continue;
        for (auto& c : list_dir(t.path)) {
            if (!c.dir || !has_files(c.path)) continue;
            PI p;
            p.kind = 2;
            p.src = c.path;
            p.title_id = std::stoull(t.name, nullptr, 16);
            out.push_back(std::move(p));
        }
    }
}

static bool discover(const fs::path& src, const Options& o, std::vector<PI>& pk) {
    fs::path upd = src / "updates", dlc = src / "dlc";
    bool has_upd = dir_exists(upd);
    auto looks_content = [&](const fs::path& d) { return dir_exists(d / "exefs") || dir_exists(d / "romfs"); };
    if (dir_exists(src / "base")) {
        PI base;
        base.kind = 0;
        base.src = src / "base";
        resolve_ids(base, o.has_title, o.title_id);
        if (has_files(base.src)) {
            uint64_t tid = base.title_id;
            pk.push_back(std::move(base));
            if (has_upd) collect_updates(upd, tid, 0, pk);
        } else if (has_upd) {
            collect_updates(upd, o.has_title ? o.title_id : 0, 1, pk);
        }
        if (dir_exists(dlc)) collect_dlcs(dlc, pk);
    } else if (has_upd) {
        collect_updates(upd, o.has_title ? o.title_id : 0, 1, pk);
        if (dir_exists(dlc)) collect_dlcs(dlc, pk);
    } else if (looks_content(src)) {
        PI base;
        base.kind = 0;
        base.src = src;
        resolve_ids(base, o.has_title, o.title_id);
        pk.push_back(std::move(base));
    } else {
        return fail("folder is neither a dump (base/updates/dlc) nor a content directory (exefs/ or romfs/)");
    }
    if (pk.empty()) return fail("no packages found in the folder");
    return true;
}

// ---------------------------------------------------------------- meta
static void tlv(std::string& out, uint16_t type, const std::string& payload) {
    uint16_t r = 0;
    uint32_t sz = (uint32_t)payload.size();
    out.append((const char*)&type, 2);
    out.append((const char*)&r, 2);
    out.append((const char*)&sz, 4);
    out += payload;
}

static void put_localized(std::string& body, const std::string& lang, const std::string& data) {
    body.push_back((char)lang.size());
    body += lang;
    uint32_t n = (uint32_t)data.size();
    body.append((const char*)&n, 4);
    body += data;
}

// ---------------------------------------------------------------- writer
struct Job {
    bool ready = false, big = false, ok = true;
    uint8_t codec = 0;
    uint8_t sha[32] = {};
    uint64_t size = 0;
    std::vector<char> payload;
    std::string e;
};

struct Out {
    std::ofstream f;
    uint64_t cursor = 0; // logical write position
    void write(const void* p, size_t n) {
        f.write((const char*)p, (std::streamsize)n);
        cursor += n;
    }
    void zeros(uint64_t n) {
        static const char z[4096] = {};
        while (n) {
            size_t k = (size_t)std::min<uint64_t>(n, sizeof z);
            write(z, k);
            n -= k;
        }
    }
    void seek(uint64_t pos) {
        f.seekp((std::streamoff)pos);
        cursor = pos;
    }
};

static void prep_small(Job& j, FileObj& fo, ZSTD_CCtx* cc, int level) {
    std::vector<char> data;
    {
        std::ifstream in(fo.src, std::ios::binary);
        if (!in) { j.ok = false; j.e = "could not open " + to_u8(fo.src.wstring()); return; }
        data.resize((size_t)j.size);
        in.read(data.data(), (std::streamsize)j.size);
        if ((uint64_t)in.gcount() != j.size) { j.ok = false; j.e = "file changed while packing: " + to_u8(fo.src.wstring()); return; }
    }
    Sha256 sh;
    sh.update(data.data(), data.size());
    sh.finish(j.sha);
    j.codec = 0;
    if (level > 0 && !data.empty()) {
        size_t cap = ZSTD_compressBound(data.size());
        std::vector<char> comp(cap);
        size_t n = ZSTD_compress2(cc, comp.data(), cap, data.data(), data.size());
        if (!ZSTD_isError(n) && n < data.size()) {
            comp.resize(n);
            j.payload = std::move(comp);
            j.codec = 1;
            return;
        }
    }
    j.payload = std::move(data);
}

static bool pack_big(Out& out, FileObj& fo, int level, std::map<std::string, std::tuple<uint64_t, uint64_t, uint8_t>>& seen,
                     std::vector<char>& ibuf) {
    constexpr size_t CH = 4 << 20;
    ibuf.resize(CH);
    std::ifstream in(fo.src, std::ios::binary);
    if (!in) return fail("could not open " + to_u8(fo.src.wstring()));
    Sha256 sh;
    uint64_t left = fo.size;
    while (left) {
        size_t n = (size_t)std::min<uint64_t>(left, CH);
        in.read(ibuf.data(), (std::streamsize)n);
        if ((size_t)in.gcount() != n) return fail("file changed while packing: " + to_u8(fo.src.wstring()));
        sh.update(ibuf.data(), n);
        left -= n;
    }
    sh.finish(fo.sha);
    std::string key((const char*)fo.sha, 32);
    auto it = seen.find(key);
    if (it != seen.end()) {
        fo.eoff = std::get<0>(it->second);
        fo.esize = std::get<1>(it->second);
        fo.codec = std::get<2>(it->second);
        return true;
    }
    uint64_t aligned = (out.cursor + 15) & ~15ull;
    out.zeros(aligned - out.cursor);
    fo.eoff = aligned;
    bool compressed = false;
    uint64_t stored = 0;
    if (level > 0) {
        in.clear();
        in.seekg(0);
        ZSTD_CCtx* cc = ZSTD_createCCtx();
        ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, level);
        ZSTD_CCtx_setPledgedSrcSize(cc, fo.size);
        std::vector<char> obuf(ZSTD_CStreamOutSize());
        bool bail = false;
        uint64_t rem_in = fo.size, consumed = 0;
        while (rem_in && !bail) {
            size_t n = (size_t)std::min<uint64_t>(rem_in, CH);
            in.read(ibuf.data(), (std::streamsize)n);
            if ((size_t)in.gcount() != n) { ZSTD_freeCCtx(cc); return fail("file changed while packing"); }
            rem_in -= n;
            consumed += n;
            ZSTD_EndDirective mode = rem_in ? ZSTD_e_continue : ZSTD_e_end;
            ZSTD_inBuffer ib{ibuf.data(), n, 0};
            size_t rem;
            do {
                ZSTD_outBuffer ob{obuf.data(), obuf.size(), 0};
                rem = ZSTD_compressStream2(cc, &ob, &ib, mode);
                if (ZSTD_isError(rem)) { ZSTD_freeCCtx(cc); return fail(std::string("error zstd: ") + ZSTD_getErrorName(rem)); }
                out.write(obuf.data(), ob.pos);
                stored += ob.pos;
                if (stored >= consumed) { bail = true; break; }
            } while (mode == ZSTD_e_end ? rem != 0 : ib.pos < ib.size);
        }
        ZSTD_freeCCtx(cc);
        compressed = !bail;
    }
    if (!compressed) {
        out.seek(aligned);
        in.clear();
        in.seekg(0);
        left = fo.size;
        while (left) {
            size_t n = (size_t)std::min<uint64_t>(left, CH);
            in.read(ibuf.data(), (std::streamsize)n);
            if ((size_t)in.gcount() != n) return fail("file changed while packing");
            out.write(ibuf.data(), n);
            left -= n;
        }
        fo.esize = fo.size;
        fo.codec = 0;
    } else {
        fo.esize = stored;
        fo.codec = 1;
    }
    seen[key] = {fo.eoff, fo.esize, fo.codec};
    return true;
}

static bool write_extents(Out& out, Tree& tree, int level) {
    size_t n = tree.files.size();
    std::vector<Job> jobs(n);
    for (size_t i = 0; i < n; ++i) {
        std::error_code ec;
        uint64_t sz = fs::file_size(tree.files[i]->src, ec);
        if (ec) return fail("could not read the size of " + to_u8(tree.files[i]->src.wstring()));
        tree.files[i]->size = sz;
        jobs[i].size = sz;
        jobs[i].big = sz > BIG_FILE;
    }

    unsigned nt = std::thread::hardware_concurrency();
    if (nt == 0) nt = 4;
    nt = std::max(1u, std::min(nt, 16u));
    const size_t WINDOW = nt * 2 + 2;

    std::mutex mu;
    std::condition_variable cv;
    size_t consumed = 0;
    uint64_t inflight = 0;
    bool stop = false;
    std::atomic<size_t> claim{0};

    std::vector<std::thread> pool;
    for (unsigned t = 0; t < nt; ++t)
        pool.emplace_back([&] {
            ZSTD_CCtx* cc = ZSTD_createCCtx();
            ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, level > 0 ? level : 3);
            for (;;) {
                size_t i = claim++;
                if (i >= n) break;
                Job& j = jobs[i];
                uint64_t cost = j.big ? 0 : j.size * 2;
                {
                    std::unique_lock<std::mutex> lk(mu);
                    cv.wait(lk, [&] {
                        return stop || i == consumed || (i < consumed + WINDOW && inflight + cost <= MEM_BUDGET);
                    });
                    if (stop) break;
                    inflight += cost;
                }
                if (!j.big) prep_small(j, *tree.files[i], cc, level);
                {
                    std::lock_guard<std::mutex> lk(mu);
                    j.ready = true;
                }
                cv.notify_all();
            }
            ZSTD_freeCCtx(cc);
        });

    std::map<std::string, std::tuple<uint64_t, uint64_t, uint8_t>> seen;
    std::vector<char> ibuf;
    bool ok = true;
    uint64_t bytes = 0;
    ULONGLONG last = 0;
    for (size_t i = 0; i < n && ok; ++i) {
        Job& j = jobs[i];
        {
            std::unique_lock<std::mutex> lk(mu);
            cv.wait(lk, [&] { return j.ready; });
        }
        FileObj& fo = *tree.files[i];
        if (!j.ok) {
            ok = fail(j.e);
        } else if (j.big) {
            ok = pack_big(out, fo, level, seen, ibuf);
        } else {
            memcpy(fo.sha, j.sha, 32);
            std::string key((const char*)j.sha, 32);
            auto it = seen.find(key);
            if (fo.size == 0) {
                fo.eoff = 0; fo.esize = 0; fo.codec = 0;
            } else if (it != seen.end()) {
                fo.eoff = std::get<0>(it->second);
                fo.esize = std::get<1>(it->second);
                fo.codec = std::get<2>(it->second);
            } else {
                uint64_t aligned = (out.cursor + 15) & ~15ull;
                out.zeros(aligned - out.cursor);
                fo.eoff = aligned;
                out.write(j.payload.data(), j.payload.size());
                fo.esize = j.payload.size();
                fo.codec = j.codec;
                seen[key] = {fo.eoff, fo.esize, fo.codec};
            }
        }
        if (ok && !out.f) ok = fail("write error (disk full?)");
        bytes += fo.size;
        {
            std::lock_guard<std::mutex> lk(mu);
            j.payload = std::vector<char>();
            inflight -= std::min<uint64_t>(inflight, j.big ? 0 : j.size * 2);
            consumed = i + 1;
        }
        cv.notify_all();
        ULONGLONG now = GetTickCount64();
        if (now - last >= 200 || i + 1 == n) {
            last = now;
            printf("\r  %llu/%llu files (%u%%)  %.1f MiB   ", (unsigned long long)(i + 1), (unsigned long long)n,
                   (unsigned)((i + 1) * 100 / n), bytes / 1048576.0);
            fflush(stdout);
        }
    }
    {
        std::lock_guard<std::mutex> lk(mu);
        stop = true;
    }
    cv.notify_all();
    for (auto& th : pool) th.join();
    printf("\n");
    return ok;
}

static fs::path unique_out(const fs::path& p) {
    std::error_code ec;
    if (!fs::exists(p, ec)) return p;
    for (int i = 2;; ++i) {
        fs::path q = p.parent_path() / (p.stem().wstring() + L"_" + std::to_wstring(i) + p.extension().wstring());
        if (!fs::exists(q, ec)) return q;
    }
}

static bool pack_dir(const fs::path& src_in, const Options& o) {
    // Application metadata that comes from files: read before starting.
    std::string icon_data;
    std::map<std::string, std::string> loc_icons;
    if (!o.icon.empty() && !slurp(o.icon, icon_data)) return fail("could not read icon " + to_u8(o.icon.wstring()));
    if (o.icon.empty()) {
        // Without --icon: use icon.jpg / icon.jpeg / icon.png from the folder root, if present.
        for (const wchar_t* n : {L"icon.jpg", L"icon.jpeg", L"icon.png"}) {
            fs::path q = src_in / n;
            std::error_code ec;
            if (fs::is_regular_file(q, ec) && slurp(q, icon_data) && !icon_data.empty()) {
                printf("Icon: %s\n", to_u8(q.filename().wstring()).c_str());
                break;
            }
            icon_data.clear();
        }
    }
    for (auto& kv : o.lang_icons)
        if (!slurp(kv.second, loc_icons[kv.first])) return fail("could not read icon " + to_u8(kv.second.wstring()));
    for (auto& kv : o.lang_names)
        if (kv.first.empty() || kv.first.size() > 255) return fail("invalid language tag: " + kv.first);
    for (auto& kv : o.lang_icons)
        if (kv.first.empty() || kv.first.size() > 255) return fail("invalid language tag: " + kv.first);

    fs::path src = fs::absolute(src_in);
    while (src.filename().empty() && src.has_parent_path() && src != src.parent_path()) src = src.parent_path();
    std::wstring label = src.filename().wstring();
    if (label.empty()) label = L"packed";
    fs::path out_path = unique_out(src.parent_path() / (label + L"_packed.nup"));

    std::vector<PI> pkgs;
    if (!discover(src, o, pkgs)) return false;

    bool has_base = false;
    for (auto& p : pkgs) has_base |= p.kind == 0;
    if (!has_base)
        for (auto& p : pkgs)
            if (p.kind == 1) p.flags |= 1;

    for (size_t i = 0; i < pkgs.size(); ++i) {
        const char* kn = pkgs[i].kind == 0 ? "base" : pkgs[i].kind == 1 ? "update" : "addon";
        printf("[%zu/%zu] %s  title=%016llx  version=%u  <- %s\n", i + 1, pkgs.size(), kn,
               (unsigned long long)pkgs[i].title_id, pkgs[i].version, to_u8(pkgs[i].src.filename().wstring()).c_str());
        if (pkgs[i].kind == 0 && pkgs[i].title_id == 0)
            printf("  Warning: could not read the title id (missing exefs/main.npdm); use --title-id HEX\n");
    }

    Tree tree;
    tree.keep_listings = o.keep_listings;
    std::vector<DirObj*> roots;
    for (auto& p : pkgs) roots.push_back(tree.walk(p.src, ""));
    for (auto* r : roots) tree.rec(r);

    uint32_t dir_count = (uint32_t)tree.dirs.size(), file_count = (uint32_t)tree.files.size();
    std::unordered_map<std::string, uint32_t> pool_idx;
    std::string pool;
    auto intern = [&](const std::string& s) -> uint32_t {
        auto it = pool_idx.find(s);
        if (it != pool_idx.end()) return it->second;
        uint32_t off = (uint32_t)pool.size();
        pool += s;
        pool_idx[s] = off;
        return off;
    };
    for (auto* d : tree.dirs) intern(d->name);
    for (auto* f : tree.files) intern(f->name);

    // files per directory (to detect empty exefs/romfs)
    std::vector<uint64_t> fcount(dir_count, 0);
    for (size_t i = dir_count; i-- > 0;) {
        const DirObj* d = tree.dirs[i];
        uint64_t t = 0;
        for (auto& k : d->kids) t += k.second ? 1 : fcount[k.first->id];
        fcount[i] = t;
    }
    std::vector<Package> recs(pkgs.size());
    for (size_t i = 0; i < pkgs.size(); ++i) {
        Package& r = recs[i];
        memset(&r, 0, sizeof r);
        r.title_id = pkgs[i].title_id;
        r.root_dir = roots[i]->id;
        r.exefs_dir = r.romfs_dir = 0xFFFFFFFFu;
        r.version = pkgs[i].version;
        r.kind = pkgs[i].kind;
        r.flags = pkgs[i].flags;
        for (auto& k : roots[i]->kids)
            if (k.first && fcount[k.first->id]) {
                if (k.first->name == "exefs") r.exefs_dir = k.first->id;
                else if (k.first->name == "romfs") r.romfs_dir = k.first->id;
            }
    }

    uint64_t toc_size = sizeof(TocHeader) + recs.size() * sizeof(Package) + (uint64_t)dir_count * sizeof(Dir) +
                        (uint64_t)file_count * sizeof(File) + tree.children.size() * 4 + pool.size();
    uint64_t blob_offset = (0x80 + toc_size + 15) & ~15ull;

    fs::path tmp = out_path;
    tmp += L".part";
    Out out;
    static std::vector<char> obuf(4 << 20);
    out.f.rdbuf()->pubsetbuf(obuf.data(), (std::streamsize)obuf.size());
    out.f.open(tmp, std::ios::binary | std::ios::trunc);
    if (!out.f) return fail("could not create " + to_u8(tmp.wstring()));
    out.zeros(blob_offset);

    printf("Packing (zstd level %d)...\n", o.level);
    bool ok = write_extents(out, tree, o.level);

    std::vector<std::pair<uint64_t, uint32_t>> meta_offs(pkgs.size());
    if (ok) {
        size_t app_idx = 0;
        for (size_t i = 0; i < pkgs.size(); ++i)
            if (pkgs[i].kind == 0) { app_idx = i; break; }
        for (size_t i = 0; i < pkgs.size(); ++i) {
            std::vector<std::pair<uint16_t, std::string>> rs;
            if (!pkgs[i].npdm.empty()) rs.push_back({1, pkgs[i].npdm});
            if (i == app_idx) {
                if (!o.display_version.empty()) rs.push_back({4, o.display_version});
                // Without --name, the default title is the folder name.
                rs.push_back({5, o.name.empty() ? to_u8(label) : o.name});
                if (!o.publisher.empty()) rs.push_back({6, o.publisher});
                if (!icon_data.empty()) rs.push_back({3, icon_data});
                if (!o.lang_names.empty()) {
                    std::string body;
                    for (auto& kv : o.lang_names) put_localized(body, kv.first, kv.second);
                    rs.push_back({9, body});
                }
                if (!loc_icons.empty()) {
                    std::string body;
                    for (auto& kv : loc_icons) put_localized(body, kv.first, kv.second);
                    rs.push_back({10, body});
                }
            }
            if (pkgs[i].has_build) rs.push_back({7, std::string((const char*)pkgs[i].build, 32)});
            rs.push_back({8, to_u8(label)});
            std::sort(rs.begin(), rs.end(), [](auto& a, auto& b) { return a.first < b.first; });
            std::string block;
            for (auto& r : rs) tlv(block, r.first, r.second);
            meta_offs[i] = {out.cursor, (uint32_t)block.size()};
            out.write(block.data(), block.size());
        }
    }
    if (ok && !out.f) ok = fail("write error (disk full?)");

    if (ok) {
        std::vector<uint8_t> toc(toc_size, 0);
        size_t pos = 0;
        TocHeader th{};
        memcpy(&th.magic, "TOC\x01", 4);
        th.package_count = (uint32_t)recs.size();
        th.dir_count = dir_count;
        th.file_count = file_count;
        th.string_pool_off = toc_size - pool.size();
        th.string_pool_size = pool.size();
        memcpy(toc.data(), &th, sizeof th);
        pos = sizeof th;
        for (size_t i = 0; i < recs.size(); ++i) {
            recs[i].meta_offset = meta_offs[i].first;
            recs[i].meta_size = meta_offs[i].second;
            memcpy(toc.data() + pos, &recs[i], sizeof(Package));
            pos += sizeof(Package);
        }
        for (auto* d : tree.dirs) {
            Dir x{};
            x.name_off = intern(d->name);
            x.name_len = (uint32_t)d->name.size();
            x.first_child = d->first;
            x.child_count = d->count;
            memcpy(toc.data() + pos, &x, sizeof x);
            pos += sizeof x;
        }
        for (auto* f : tree.files) {
            File x{};
            x.name_off = intern(f->name);
            x.name_len = (uint32_t)f->name.size();
            x.size = f->size;
            x.extent_offset = f->eoff;
            x.extent_size = f->esize;
            memcpy(x.sha256, f->sha, 32);
            x.codec = f->codec;
            memcpy(toc.data() + pos, &x, sizeof x);
            pos += sizeof x;
        }
        for (uint32_t c : tree.children) {
            if (c >= FILE_TAG) c = dir_count + (c - FILE_TAG);
            memcpy(toc.data() + pos, &c, 4);
            pos += 4;
        }
        memcpy(toc.data() + pos, pool.data(), pool.size());

        Superblock sb{};
        memcpy(sb.magic, "NUP\x01", 4);
        sb.header_size = 0x80;
        sb.header_version = 1;
        sb.toc_offset = 0x80;
        sb.toc_size = toc_size;
        {
            Sha256 sh;
            sh.update(toc.data(), toc.size());
            sh.finish(sb.toc_sha256);
        }
        sb.blob_offset = blob_offset;
        sb.file_size = out.cursor;
        sb.package_count = (uint32_t)recs.size();
        {
            Sha256 sh;
            for (auto& r : recs) {
                sh.update(&r.title_id, 8);
                sh.update(&r.version, 4);
                sh.update(&r.kind, 1);
            }
            uint8_t d[32];
            sh.finish(d);
            memcpy(sb.uuid, d, 16);
        }
        uint64_t final_size = out.cursor;
        out.seek(0);
        out.write(&sb, sizeof sb);
        out.write(toc.data(), toc.size());
        out.f.flush();
        if (!out.f) ok = fail("write error (disk full?)");
        out.f.close();
        if (ok) {
            std::error_code ec;
            if (fs::file_size(tmp, ec) != final_size) fs::resize_file(tmp, final_size, ec);
        }
        if (ok) {
            std::error_code ec;
            fs::rename(tmp, out_path, ec);
            if (ec) ok = fail("could not rename the output file");
        }
        if (ok) printf("Done: %zu package(s), %u files -> %s\n", pkgs.size(), file_count,
                       to_u8(out_path.wstring()).c_str());
    } else {
        out.f.close();
    }
    if (!ok) {
        std::error_code ec;
        fs::remove(tmp, ec);
    }
    return ok;
}

} // namespace pk

static void pause_exit() {
    printf("\nPress Enter to exit...");
    fflush(stdout);
    getchar();
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);

    std::vector<fs::path> inputs;
    fs::path outdir;
    bool verify = true;
    pk::Options po;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        bool more = i + 1 < argc;
        if ((a == L"-o" || a == L"--out") && more) outdir = argv[++i];
        else if (a == L"--no-verify") verify = false;
        else if (a == L"--keep-listings") po.keep_listings = true;
        else if (a == L"--level" && more) po.level = _wtoi(argv[++i]);
        else if (a == L"--title-id" && more) { po.has_title = true; po.title_id = wcstoull(argv[++i], nullptr, 16); }
        else if (a == L"--name" && more) po.name = to_u8(argv[++i]);
        else if (a == L"--publisher" && more) po.publisher = to_u8(argv[++i]);
        else if (a == L"--icon" && more) po.icon = argv[++i];
        else if ((a == L"--lang-name" || a == L"--lang-icon") && more) {
            std::wstring v = argv[++i];
            size_t eq = v.find(L'=');
            if (eq == std::wstring::npos || eq == 0 || eq + 1 >= v.size()) {
                fprintf(stderr, "ERROR: %s expects LANG=VALUE\n", to_u8(a).c_str());
                pause_exit();
                return 1;
            }
            std::string lang = to_u8(v.substr(0, eq));
            for (auto& c : lang) c = (char)tolower((unsigned char)c);
            if (a == L"--lang-name") po.lang_names[lang] = to_u8(v.substr(eq + 1));
            else po.lang_icons[lang] = fs::path(v.substr(eq + 1));
        }
        else if (a == L"--display-version" && more) po.display_version = to_u8(argv[++i]);
        else inputs.emplace_back(a);
    }
    if (inputs.empty()) {
        printf("nup_extract - drag onto this program:\n");
        printf("  * a .nup file  -> extracts it into a folder\n");
        printf("  * a folder     -> creates <folder>_packed.nup\n\n");
        printf("Usage: nup_extract file.nup [-o folder] [--no-verify]\n");
        printf("       nup_extract folder [--level N] [--title-id HEX] [--name N] [--publisher P]\n");
        printf("                         [--display-version V] [--keep-listings]\n");
        printf("                         [--icon path] [--lang-name ja=Name] [--lang-icon ja=path]\n");
        pause_exit();
        return 1;
    }
    int rc = 0;
    for (auto& in : inputs) {
        printf("== %s\n", to_u8(in.filename().wstring()).c_str());
        err.clear();
        bool ok;
        try {
            std::error_code ec;
            if (fs::is_directory(in, ec)) ok = pk::pack_dir(in, po);
            else {
                fs::path o = (inputs.size() > 1) ? fs::path() : outdir;
                ok = extract_nup(in, o, verify);
            }
        } catch (const std::exception& e) {
            ok = fail(e.what());
        }
        if (!ok) {
            fprintf(stderr, "ERROR: %s\n", err.c_str());
            rc = 1;
        }
    }
    pause_exit();
    return rc;
}
