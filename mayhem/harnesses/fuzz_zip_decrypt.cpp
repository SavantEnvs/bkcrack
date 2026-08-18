// mayhem/harnesses/fuzz_zip_decrypt.cpp -- fuzz bkcrack's ZIP re-encoding/decrypt-rewrite path.
//
// A second, distinct code path over the same untrusted-container surface as fuzz_zip.cpp:
// Zip::decrypt() re-reads and rewrites the WHOLE archive (not just the central directory) --
// LocalFileHeader::read() at each traditionally-encrypted entry's offset, the ZIP64 extra-field
// substitution logic, the optional data-descriptor variant (with/without its optional signature word,
// 32-bit vs 64-bit sizes), and a second central-directory pass that rewrites header offsets, plus the
// ZIP64 EOCD/EOCD-locator/EOCD tail. None of this depends on knowing the real encryption keys -- decrypt()
// only XORs bytes with whatever Keys it is given, so a fixed, default-constructed Keys{} exercises the
// exact same parsing/rewriting logic a real recovered key would, without needing (or wanting) the actual
// Biham-Kocher search: that search (Zreduction/Attack) is compute-bound and stays OUT of the fuzz
// surface, per the harness design; this harness never calls into it.
//
// BOUNDING (SPEC 6b): decrypt() walks the central directory to build a map of encrypted entries (bounded
// exactly as in fuzz_zip.cpp: a failed read on a malformed record ends the walk), then does two linear
// passes over the input stream copying/transforming bytes -- both passes are driven by the ACTUAL stream
// length via std::istreambuf_iterator, so `std::views::take` on an inconsistent/out-of-order offset just
// stops at end-of-stream rather than looping; there is no unbounded loop to guard here. We still cap the
// overall input size (kMaxInputSize) as defense in depth -- output goes to a throwaway in-memory
// std::ostringstream, never touching the filesystem.
#include <bkcrack/Keys.hpp>
#include <bkcrack/Progress.hpp>
#include <bkcrack/Zip.hpp>

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>

namespace
{
constexpr std::size_t kMaxInputSize = 1 << 20; // 1 MiB
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    if (size > kMaxInputSize)
        return 0;

    auto inputStream = std::istringstream{std::string{reinterpret_cast<const char*>(data), size}};

    try
    {
        const auto archive = Zip{inputStream};

        auto output      = std::ostringstream{};
        auto progressLog  = std::ostringstream{}; // Progress just wants somewhere to log; discarded.
        auto progress     = Progress{progressLog};
        const auto keys   = Keys{}; // default state -- decrypt() only needs SOME keys to XOR with.

        archive.decrypt(output, keys, progress);
        (void)output.str();
    }
    catch (const Zip::Error&)
    {
        // Expected: not a valid zip, no traditionally-encrypted entries laid out the way decrypt()
        // requires, split/unsupported structures, etc.
    }
    catch (const std::length_error&)
    {
        // See fuzz_zip.cpp -- a declared string length can hit this before any allocator OOM.
    }
    catch (const std::bad_alloc&)
    {
        // See fuzz_zip.cpp -- an expected rejection of an oversized declared size, not a crash.
    }

    return 0;
}
