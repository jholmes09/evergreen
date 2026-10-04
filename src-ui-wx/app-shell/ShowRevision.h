#pragma once

/***************************************************************
 * This source files comes from the xLights project
 * https://www.xlights.org
 * https://github.com/xLightsSequencer/xLights
 * See the github commit history for a record of contributing
 * developers.
 * Copyright claimed based on commit dates recorded in Github
 * License: https://github.com/xLightsSequencer/xLights/blob/master/License.txt
 **************************************************************/

// Show folder revision stamp.
//
// A show folder may carry a rev="..." attribute on the root element of
// xlights_networks.xml and/or xlights_rgbeffects.xml. When present, the folder
// only opens after the matching entry is confirmed, and the stamp is then removed
// from every file carrying it.
//
// A stamp may also carry revd="...": a sealed countdown (stamp date, days allowed,
// latest date seen, clock-rollback count). While days remain the folder opens
// after a notice showing the days left; at zero the entry is required. The latest
// date only moves forward, and each open with the clock behind it costs a day. A
// missing, edited or mismatched countdown counts as zero days. The countdown and
// the stamp are also remembered on this computer, so restoring an older copy of
// the files or removing the attributes does not reset or clear them.
//
// Shared by xLights and xSchedule; header-only so neither project file needs to change.

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <wx/config.h>
#include <wx/datetime.h>
#include <wx/file.h>
#include <wx/filefn.h>
#include <wx/filename.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include <wx/window.h>
#include <wx/xml/xml.h>

namespace ShowRevision {

namespace detail {

class Sha256 {
public:
    Sha256() { Reset(); }

    void Reset()
    {
        static const uint32_t init[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
        std::memcpy(_h, init, sizeof(_h));
        _len = 0;
        _used = 0;
    }

    void Update(const uint8_t* data, size_t n)
    {
        for (size_t i = 0; i < n; i++) {
            _buf[_used++] = data[i];
            if (_used == 64) {
                Block(_buf);
                _used = 0;
            }
        }
        _len += (uint64_t)n * 8;
    }

    void Final(uint8_t out[32])
    {
        uint64_t len = _len;
        uint8_t pad = 0x80;
        Update(&pad, 1);
        uint8_t zero = 0;
        while (_used != 56) {
            Update(&zero, 1);
        }
        uint8_t lenBytes[8];
        for (int i = 0; i < 8; i++) {
            lenBytes[i] = (uint8_t)(len >> (56 - 8 * i));
        }
        Update(lenBytes, 8);
        for (int i = 0; i < 8; i++) {
            out[4 * i] = (uint8_t)(_h[i] >> 24);
            out[4 * i + 1] = (uint8_t)(_h[i] >> 16);
            out[4 * i + 2] = (uint8_t)(_h[i] >> 8);
            out[4 * i + 3] = (uint8_t)(_h[i]);
        }
    }

private:
    static uint32_t Rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void Block(const uint8_t* p)
    {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = _h[0], b = _h[1], c = _h[2], d = _h[3], e = _h[4], f = _h[5], g = _h[6], h = _h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        _h[0] += a; _h[1] += b; _h[2] += c; _h[3] += d;
        _h[4] += e; _h[5] += f; _h[6] += g; _h[7] += h;
    }

    uint32_t _h[8];
    uint64_t _len;
    uint8_t _buf[64];
    size_t _used;
};

constexpr int kRounds = 100000;
constexpr size_t kSaltBytes = 16;
constexpr size_t kDigestBytes = 32;

inline bool FromHex(const std::string& hex, uint8_t* out, size_t n)
{
    if (hex.size() != n * 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < n; i++) {
        int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return true;
}

// d = H(salt || entry), then d = H(d || salt) for the remaining rounds.
inline void Derive(const uint8_t salt[kSaltBytes], const std::string& entry, uint8_t out[kDigestBytes])
{
    Sha256 s;
    s.Update(salt, kSaltBytes);
    s.Update((const uint8_t*)entry.data(), entry.size());
    s.Final(out);
    for (int i = 1; i < kRounds; i++) {
        s.Reset();
        s.Update(out, kDigestBytes);
        s.Update(salt, kSaltBytes);
        s.Final(out);
    }
}

// Locate name="<hex>" (rev by default) inside the root start tag (e.g. "<Networks"). On success,
// start/len cover the attribute including its leading whitespace, and value is the hex.
inline bool FindStamp(const std::string& xml, const char* rootTag, size_t& start, size_t& len, std::string& value,
                      const char* name = "rev")
{
    size_t tag = xml.find(rootTag);
    if (tag == std::string::npos) return false;
    size_t tagEnd = xml.find('>', tag);
    if (tagEnd == std::string::npos) return false;
    const std::string key = std::string(name) + "=\"";
    size_t pos = tag;
    while (true) {
        pos = xml.find(key, pos);
        if (pos == std::string::npos || pos > tagEnd) return false;
        char before = xml[pos - 1];
        if (before == ' ' || before == '\t' || before == '\r' || before == '\n') break;
        pos += key.size();
    }
    size_t valStart = pos + key.size();
    size_t valEnd = xml.find('"', valStart);
    if (valEnd == std::string::npos || valEnd > tagEnd) return false;
    size_t attrStart = pos;
    while (attrStart > tag && (xml[attrStart - 1] == ' ' || xml[attrStart - 1] == '\t')) attrStart--;
    start = attrStart;
    len = valEnd + 1 - attrStart;
    value = xml.substr(valStart, valEnd - valStart);
    return true;
}

inline bool ReadAll(const wxString& path, std::string& out)
{
    wxFile f;
    if (!f.Open(path, wxFile::read)) return false;
    wxFileOffset n = f.Length();
    if (n < 0) return false;
    out.resize((size_t)n);
    return n == 0 || f.Read(&out[0], (size_t)n) == (ssize_t)n;
}

inline bool WriteAll(const wxString& path, const std::string& data)
{
    wxString tmp = path + ".tmp";
    {
        wxFile f;
        if (!f.Create(tmp, true)) return false;
        if (!data.empty() && f.Write(data.data(), data.size()) != data.size()) return false;
        if (!f.Flush()) return false;
    }
    return wxRenameFile(tmp, path, true);
}

inline std::string ToHex(const uint8_t* p, size_t n)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        out += digits[p[i] >> 4];
        out += digits[p[i] & 15];
    }
    return out;
}

inline void HashOf(const std::string& data, uint8_t out[kDigestBytes])
{
    Sha256 s;
    s.Update((const uint8_t*)data.data(), data.size());
    s.Final(out);
}

// Must match the stamping tool.
constexpr const char* kSealKey = "Evergreen show revision countdown v1";
constexpr size_t kNonceBytes = 4;
constexpr size_t kStateBytes = 12;
constexpr size_t kMacBytes = 16;
constexpr size_t kSealedHex = (kNonceBytes + kStateBytes + kMacBytes) * 2;
constexpr int kMaxDays = 3650;

struct Countdown {
    uint32_t stampDay = 0; // days since 1970-01-01, local calendar date
    uint16_t allowed = 0;
    uint32_t lastSeen = 0;
    uint16_t penalty = 0;
};

inline int DaysLeft(const Countdown& c)
{
    long left = (long)c.allowed - ((long)c.lastSeen - (long)c.stampDay) - (long)c.penalty;
    return left < 0 ? 0 : (int)left;
}

// Today's local calendar date as days since 1970-01-01.
inline uint32_t Today()
{
    wxDateTime t = wxDateTime::Today();
    long y = t.GetYear();
    unsigned m = (unsigned)t.GetMonth() + 1;
    unsigned d = t.GetDay();
    if (m <= 2) y--;
    const long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long days = era * 146097L + (long)doe - 719468L;
    return days < 0 ? 0 : (uint32_t)days;
}

inline std::string KeyFor(const uint8_t salt[kSaltBytes])
{
    uint8_t k[kDigestBytes];
    HashOf(std::string(kSealKey) + std::string((const char*)salt, kSaltBytes), k);
    return std::string((const char*)k, kDigestBytes);
}

// revd = nonce || (state XOR H(key||"ks"||nonce)) || H(key||"mac"||nonce||ct)[0..16)
inline std::string Seal(const uint8_t salt[kSaltBytes], const Countdown& c)
{
    uint8_t buf[kNonceBytes + kStateBytes + kMacBytes];
    std::random_device rd;
    for (size_t i = 0; i < kNonceBytes; i++) buf[i] = (uint8_t)rd();
    uint8_t* st = buf + kNonceBytes;
    st[0] = (uint8_t)(c.stampDay >> 24); st[1] = (uint8_t)(c.stampDay >> 16);
    st[2] = (uint8_t)(c.stampDay >> 8);  st[3] = (uint8_t)c.stampDay;
    st[4] = (uint8_t)(c.allowed >> 8);   st[5] = (uint8_t)c.allowed;
    st[6] = (uint8_t)(c.lastSeen >> 24); st[7] = (uint8_t)(c.lastSeen >> 16);
    st[8] = (uint8_t)(c.lastSeen >> 8);  st[9] = (uint8_t)c.lastSeen;
    st[10] = (uint8_t)(c.penalty >> 8);  st[11] = (uint8_t)c.penalty;

    const std::string key = KeyFor(salt);
    const std::string nonce((const char*)buf, kNonceBytes);
    uint8_t ks[kDigestBytes];
    HashOf(key + "ks" + nonce, ks);
    for (size_t i = 0; i < kStateBytes; i++) st[i] ^= ks[i];
    uint8_t mac[kDigestBytes];
    HashOf(key + "mac" + nonce + std::string((const char*)st, kStateBytes), mac);
    std::memcpy(buf + kNonceBytes + kStateBytes, mac, kMacBytes);
    return ToHex(buf, sizeof(buf));
}

inline bool Unseal(const uint8_t salt[kSaltBytes], const std::string& hex, Countdown& c)
{
    uint8_t buf[kNonceBytes + kStateBytes + kMacBytes];
    if (hex.size() != kSealedHex || !FromHex(hex, buf, sizeof(buf))) return false;
    const std::string key = KeyFor(salt);
    const std::string nonce((const char*)buf, kNonceBytes);
    uint8_t* st = buf + kNonceBytes;
    uint8_t mac[kDigestBytes];
    HashOf(key + "mac" + nonce + std::string((const char*)st, kStateBytes), mac);
    uint8_t diff = 0;
    for (size_t i = 0; i < kMacBytes; i++) diff |= (uint8_t)(mac[i] ^ buf[kNonceBytes + kStateBytes + i]);
    if (diff != 0) return false;
    uint8_t ks[kDigestBytes];
    HashOf(key + "ks" + nonce, ks);
    for (size_t i = 0; i < kStateBytes; i++) st[i] ^= ks[i];
    c.stampDay = ((uint32_t)st[0] << 24) | ((uint32_t)st[1] << 16) | ((uint32_t)st[2] << 8) | st[3];
    c.allowed = (uint16_t)((st[4] << 8) | st[5]);
    c.lastSeen = ((uint32_t)st[6] << 24) | ((uint32_t)st[7] << 16) | ((uint32_t)st[8] << 8) | st[9];
    c.penalty = (uint16_t)((st[10] << 8) | st[11]);
    return c.allowed >= 1 && c.allowed <= kMaxDays && c.lastSeen >= c.stampDay;
}

// Set name="value" on the root start tag, replacing any existing value.
inline bool SetAttr(std::string& xml, const char* rootTag, const char* name, const std::string& value)
{
    size_t start, len;
    std::string old;
    if (FindStamp(xml, rootTag, start, len, old, name)) {
        xml.replace(start, len, std::string(" ") + name + "=\"" + value + "\"");
        return true;
    }
    size_t tag = xml.find(rootTag);
    if (tag == std::string::npos) return false;
    size_t end = xml.find('>', tag);
    if (end == std::string::npos) return false;
    if (xml[end - 1] == '/') end--;
    xml.insert(end, std::string(" ") + name + "=\"" + value + "\"");
    return true;
}

inline void RemoveAttr(std::string& xml, const char* rootTag, const char* name)
{
    size_t start, len;
    std::string old;
    if (FindStamp(xml, rootTag, start, len, old, name)) xml.erase(start, len);
}

// Settings shared by xLights and xSchedule on this computer.
inline wxString MemoryName() { return "EvergreenShow"; }

inline wxString FolderEntry(const wxString& showDir)
{
    wxFileName fn = wxFileName::DirName(showDir);
    fn.Normalize(wxPATH_NORM_DOTS | wxPATH_NORM_ABSOLUTE);
    wxString p = fn.GetPath().Lower();
    const wxScopedCharBuffer utf8 = p.ToUTF8();
    uint8_t h[kDigestBytes];
    HashOf(std::string(utf8.data(), utf8.length()), h);
    return "/ShowRevision/F" + ToHex(h, 12);
}

inline wxString StampEntry(const uint8_t salt[kSaltBytes])
{
    return "/ShowRevision/S" + ToHex(salt, kSaltBytes);
}

} // namespace detail

// The stamp attributes (name, value) currently on a show file's root element, so code
// that rewrites the file from scratch can keep them. rootTag is e.g. "<xrgb".
inline std::vector<std::pair<std::string, std::string>> StampAttrs(const wxString& path, const char* rootTag)
{
    std::vector<std::pair<std::string, std::string>> attrs;
    std::string xml;
    if (!wxFileExists(path) || !detail::ReadAll(path, xml)) return attrs;
    for (const char* name : { "rev", "revd" }) {
        size_t start, len;
        std::string value;
        if (detail::FindStamp(xml, rootTag, start, len, value, name)) attrs.emplace_back(name, value);
    }
    return attrs;
}

// Keeps the stamp when xLights rewrites xlights_networks.xml from scratch.
inline void CarryOver(const wxString& path, wxXmlNode* root)
{
    for (const auto& a : StampAttrs(path, "<Networks")) root->AddAttribute(a.first, a.second);
}

// True when the folder may be opened: no stamp, days remain on the countdown and
// the user continues, or the entry matched (the stamp is then cleared from every
// file). False when the user cancels or a show file cannot be updated. Must run
// before anything reads the show folder.
inline bool Confirm(const wxString& showDir, wxWindow* parent)
{
    struct ShowFile {
        wxString path;
        const char* root;
        std::string xml;
        bool stamped = false;
        std::string rev;
        std::string revd;
        uint8_t salt[detail::kSaltBytes];
        uint8_t expected[detail::kDigestBytes];
        bool counted = false;
        detail::Countdown countdown;
    };
    static const char* const kFiles[][2] = { { "xlights_networks.xml", "<Networks" },
                                             { "xlights_rgbeffects.xml", "<xrgb" } };
    const wxString title = "Protected File";
    const wxString notOpened = "This show folder could not be opened.";
    const wxString notUpdated = "This show folder could not be opened because a show file could not be updated.";

    // Parses rev/revd into f. False when rev is malformed.
    auto parse = [](ShowFile& f) {
        if (f.rev.size() != (detail::kSaltBytes + detail::kDigestBytes) * 2 ||
            !detail::FromHex(f.rev.substr(0, detail::kSaltBytes * 2), f.salt, detail::kSaltBytes) ||
            !detail::FromHex(f.rev.substr(detail::kSaltBytes * 2), f.expected, detail::kDigestBytes)) {
            return false;
        }
        f.stamped = true;
        f.counted = !f.revd.empty() && detail::Unseal(f.salt, f.revd, f.countdown);
        return true;
    };

    std::vector<ShowFile> files;
    for (const auto& k : kFiles) {
        ShowFile f;
        f.path = wxFileName(showDir, k[0]).GetFullPath();
        f.root = k[1];
        if (!wxFileExists(f.path) || !detail::ReadAll(f.path, f.xml)) continue;
        size_t start, len;
        if (detail::FindStamp(f.xml, f.root, start, len, f.rev)) {
            detail::FindStamp(f.xml, f.root, start, len, f.revd, "revd");
            if (!parse(f)) {
                // A malformed stamp is treated as present: refuse rather than open silently.
                wxMessageBox(notOpened, title, wxOK | wxICON_ERROR, parent);
                return false;
            }
        }
        files.push_back(std::move(f));
    }

    wxConfig memory(detail::MemoryName());
    const wxString folderEntry = detail::FolderEntry(showDir);

    std::vector<ShowFile*> stamped;
    for (auto& f : files) {
        if (f.stamped) stamped.push_back(&f);
    }

    auto isPaid = [&](const uint8_t* salt) {
        wxString v;
        return memory.Read(detail::StampEntry(salt), &v) && v == "ok";
    };

    // Puts the stamp this computer remembers for the folder back on every show file.
    // 0 = nothing usable remembered (or it was paid), 1 = done, -1 = a file could not be written.
    auto restoreRemembered = [&]() {
        wxString remembered;
        if (files.empty() || !memory.Read(folderEntry, &remembered)) return 0;
        ShowFile check;
        check.rev = remembered.BeforeFirst('|').ToStdString();
        check.revd = remembered.AfterFirst('|').ToStdString();
        if (!parse(check) || isPaid(check.salt)) {
            memory.DeleteEntry(folderEntry);
            memory.Flush();
            return 0;
        }
        stamped.clear();
        for (auto& f : files) {
            f.rev = check.rev;
            f.revd = check.revd;
            parse(f);
            if (!detail::SetAttr(f.xml, f.root, "rev", f.rev)) return -1;
            if (f.revd.empty()) {
                detail::RemoveAttr(f.xml, f.root, "revd");
            } else if (!detail::SetAttr(f.xml, f.root, "revd", f.revd)) {
                return -1;
            }
            if (!detail::WriteAll(f.path, f.xml)) return -1;
            stamped.push_back(&f);
        }
        return 1;
    };

    auto clearStamp = [&]() {
        bool allWritten = true;
        for (auto f : stamped) {
            detail::RemoveAttr(f->xml, f->root, "rev");
            detail::RemoveAttr(f->xml, f->root, "revd");
            if (!detail::WriteAll(f->path, f->xml)) allWritten = false;
        }
        memory.Write(detail::StampEntry(stamped[0]->salt), "ok");
        memory.DeleteEntry(folderEntry);
        memory.Flush();
        return allWritten;
    };

    if (stamped.empty()) {
        // The attributes were removed from a folder this computer knows is stamped: put them back.
        const int restored = restoreRemembered();
        if (restored == 0) return true;
        if (restored < 0) {
            wxMessageBox(notUpdated, title, wxOK | wxICON_ERROR, parent);
            return false;
        }
    } else if (isPaid(stamped[0]->salt)) {
        // Already confirmed on this computer (e.g. a backup restored after payment). A paid
        // stamp never replaces a different, unpaid stamp this computer knows the folder carries.
        wxString remembered;
        const bool other = memory.Read(folderEntry, &remembered) && remembered.BeforeFirst('|') != wxString(stamped[0]->rev);
        const int restored = other ? restoreRemembered() : 0;
        if (restored < 0) {
            wxMessageBox(notUpdated, title, wxOK | wxICON_ERROR, parent);
            return false;
        }
        if (restored == 0) {
            clearStamp();
            return true;
        }
    }

    const wxString stampEntry = detail::StampEntry(stamped[0]->salt);

    // Every stamped file must carry the same valid countdown, or the folder is locked.
    bool counted = true;
    detail::Countdown c = stamped[0]->countdown;
    for (auto f : stamped) {
        if (!f->counted || f->countdown.stampDay != c.stampDay || f->countdown.allowed != c.allowed) {
            counted = false;
            break;
        }
        c.lastSeen = std::max(c.lastSeen, f->countdown.lastSeen);
        c.penalty = std::max(c.penalty, f->countdown.penalty);
    }

    int daysLeft = 0;
    if (counted) {
        wxString seen;
        if (memory.Read(stampEntry, &seen)) {
            unsigned long last = 0, pen = 0;
            if (seen.BeforeFirst(',').ToULong(&last) && seen.AfterFirst(',').ToULong(&pen)) {
                c.lastSeen = std::max(c.lastSeen, (uint32_t)last);
                c.penalty = std::max(c.penalty, (uint16_t)std::min(pen, 65535UL));
            }
        }
        const uint32_t today = detail::Today();
        if (today >= c.lastSeen) {
            c.lastSeen = today;
        } else if (c.penalty < 65535) {
            c.penalty++; // clock is behind the latest date already seen
        }
        daysLeft = detail::DaysLeft(c);

        const std::string sealed = detail::Seal(stamped[0]->salt, c);
        for (auto f : stamped) {
            if (f->countdown.lastSeen == c.lastSeen && f->countdown.penalty == c.penalty) continue;
            if (!detail::SetAttr(f->xml, f->root, "revd", sealed) || !detail::WriteAll(f->path, f->xml)) {
                wxMessageBox(notUpdated, title, wxOK | wxICON_ERROR, parent);
                return false;
            }
        }
        memory.Write(stampEntry, wxString::Format("%u,%u", (unsigned)c.lastSeen, (unsigned)c.penalty));
        memory.Write(folderEntry, wxString(stamped[0]->rev) + "|" + sealed);
    } else {
        memory.Write(folderEntry, wxString(stamped[0]->rev) + "|" + stamped[0]->revd);
    }
    memory.Flush();

    const wxString locked = "Use of this show folder without payment is prohibited. Please contact Jeff Holmes Presents for more information.";
    while (true) {
        if (daysLeft > 0) {
            const wxString notice = wxString::Format(
                "Use of this show folder without payment is prohibited. This show folder will lock in %d %s. "
                "Please contact Jeff Holmes Presents for more information.",
                daysLeft, daysLeft == 1 ? "day" : "days");
            wxMessageDialog note(parent, notice, title, wxYES_NO | wxCANCEL | wxICON_WARNING);
            note.SetYesNoCancelLabels("Continue", "Enter Code", "Cancel");
            const int choice = note.ShowModal();
            if (choice == wxID_YES) return true;
            if (choice != wxID_NO) return false;
        }

        wxTextEntryDialog dlg(parent, daysLeft > 0 ? wxString("Enter the code from Jeff Holmes Presents.") : locked,
                              title, "", wxTextEntryDialogStyle | wxTE_PASSWORD);
        if (dlg.ShowModal() != wxID_OK) {
            if (daysLeft > 0) continue;
            return false;
        }

        const wxScopedCharBuffer utf8 = dlg.GetValue().ToUTF8();
        const std::string entry(utf8.data(), utf8.length());
        bool matched = false;
        for (auto f : stamped) {
            uint8_t got[detail::kDigestBytes];
            detail::Derive(f->salt, entry, got);
            uint8_t diff = 0;
            for (size_t i = 0; i < detail::kDigestBytes; i++) diff |= (uint8_t)(got[i] ^ f->expected[i]);
            if (diff == 0) { matched = true; break; }
        }
        if (matched) break;

        wxMessageBox("That entry was not accepted.", title, wxOK | wxICON_WARNING, parent);
    }

    if (!clearStamp()) {
        wxMessageBox("The show folder was opened, but a show file could not be updated. You may be asked again next time.",
                     title, wxOK | wxICON_WARNING, parent);
    }
    return true;
}

} // namespace ShowRevision
