// mayhem/harnesses/fuzz_zip.cpp -- fuzz bkcrack's ZIP CONTAINER PARSER.
//
// bkcrack's interesting attack surface for us is not the known-plaintext cryptanalysis (Attack.cpp /
// Zreduction.cpp) -- that is compute-bound by design (an O(2^38)-ish search) and fuzzing it would burn
// the whole campaign without exercising new code paths. The actual UNTRUSTED-INPUT surface is the ZIP
// container parser in bkcrack/Zip.{hpp,cpp}: it reads a local/central-directory/EOCD structure (incl.
// Zip64 and traditional-PKWARE-encryption extra fields) straight from attacker-controlled bytes to
// enumerate entries and read their raw data.
//
// This harness feeds the fuzzer's bytes directly to Zip's istream constructor (no filesystem I/O at
// all -- Zip takes an already-open std::istream&, so there is no path/extension plumbing to fight),
// walks the central directory via Zip::begin()/end() (the Iterator that decodes each
// CentralDirectoryHeader + its ExtraField blocks -- AES / Info-ZIP Unicode path / Zip64), and loads each
// entry's raw (still-compressed/encrypted) bytes via Zip::load(), which internally calls Zip::seek()
// (re-parses the local file header at the entry's declared offset).
//
// BOUNDING (SPEC 6b): a malformed archive can declare an unbounded number of central-directory records
// (each is only ~46 bytes of fixed fields) or an entry whose declared packedSize is up to 2^64-1. The
// central-directory walk in Zip::Iterator is already naturally bounded by input size -- it stops the
// instant a read fails (end of stream sets the failbit, and checkSignature() then returns false) -- but
// we still cap kMaxEntries defensively (defense in depth against a future upstream change relaxing that
// invariant), and Zip::load()'s own `count` parameter caps how many bytes of a single entry we ever
// materialize, so a single entry claiming a multi-exabyte uncompressed/packed size cannot force a huge
// allocation. Zip::Error is bkcrack's OWN exception type for "not a valid/expected zip structure" and is
// the expected outcome for the overwhelming majority of fuzzer-generated inputs -- it is caught here,
// same as bkcrack's own CLI does. We deliberately do NOT catch (...) blindly: sanitizer aborts never
// unwind as a C++ exception, so ASan/UBSan findings still surface as crashes, not swallowed exceptions.
#include <bkcrack/Zip.hpp>

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>

namespace
{
constexpr std::size_t kMaxInputSize    = 1 << 20; // 1 MiB -- plenty for a container-parser corpus
constexpr int         kMaxEntries      = 10000;   // defense in depth vs a pathological entry count
constexpr std::size_t kMaxBytesPerEntry = 1 << 16; // cap materialized bytes per entry
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size > kMaxInputSize)
        return 0;

    auto stream = std::istringstream{std::string{reinterpret_cast<const char*>(data), size}};

    try
    {
        const auto archive = Zip{stream};

        auto entryCount = 0;
        for (const auto& entry : archive)
        {
            if (++entryCount > kMaxEntries)
                break;

            // Touch every field of the parsed entry so the compiler can't elide the decode.
            const volatile auto crc               = entry.crc32;
            const volatile auto uncompressedSize  = entry.uncompressedSize;
            const volatile auto packedSize        = entry.packedSize;
            const volatile auto checkByte         = entry.checkByte;
            (void)crc;
            (void)uncompressedSize;
            (void)packedSize;
            (void)checkByte;

            try
            {
                // Re-parses the local file header at entry.offset and reads up to
                // kMaxBytesPerEntry raw bytes -- exercises Zip::seek() independently of the
                // central-directory walk above (a corrupt/misaligned local header is expected
                // to throw Zip::Error here even when the central directory parsed cleanly).
                const auto raw = archive.load(entry, kMaxBytesPerEntry);
                (void)raw;
            }
            catch (const Zip::Error&)
            {
                // Expected: local header missing/misaligned/inconsistent with the central directory.
            }
        }
    }
    catch (const Zip::Error&)
    {
        // Expected: not a valid zip archive, or a structure bkcrack doesn't support (split archives,
        // central directory encryption, ...).
    }
    catch (const std::length_error&)
    {
        // A declared filename/comment/extra-field length can be up to 65535 and bkcrack resizes a
        // std::string to it directly; on some standard library implementations an absurd combination
        // can hit an internal length_error before any allocator OOM. Not a memory-safety bug.
    }
    catch (const std::bad_alloc&)
    {
        // A declared size can legitimately request a large-but-not-crashing allocation; ASan's
        // allocator will abort() (not throw) for a genuinely out-of-bounds request, so a caught
        // bad_alloc here is an expected, non-fatal rejection, not a masked defect.
    }

    return 0;
}
