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
// xlights_networks.xml. When it is present the folder is only opened after the
// matching entry is confirmed, and the attribute is then removed so later opens
// are unaffected. Shared by xLights and xSchedule; header-only so neither
// project file needs to change.

#include <cstdint>
#include <cstring>
#include <string>

#include <wx/file.h>
#include <wx/filefn.h>
#include <wx/filename.h>
#include <wx/msgdlg.h>
#include <wx/textdlg.h>
#include <wx/window.h>

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

// Locate rev="<hex>" inside the <Networks ...> start tag. On success, start/len
// cover the attribute including its leading whitespace, and value is the hex.
inline bool FindStamp(const std::string& xml, size_t& start, size_t& len, std::string& value)
{
    size_t tag = xml.find("<Networks");
    if (tag == std::string::npos) return false;
    size_t tagEnd = xml.find('>', tag);
    if (tagEnd == std::string::npos) return false;
    const std::string key = "rev=\"";
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

} // namespace detail

// True when the folder may be opened: no stamp, or the entry matched (the stamp
// is then cleared). False when the user cancels. Must run before anything reads
// the show folder.
inline bool Confirm(const wxString& showDir, wxWindow* parent)
{
    wxFileName fn(showDir, "xlights_networks.xml");
    const wxString path = fn.GetFullPath();
    std::string xml;
    if (!wxFileExists(path) || !detail::ReadAll(path, xml)) return true;

    size_t start = 0, len = 0;
    std::string value;
    if (!detail::FindStamp(xml, start, len, value)) return true;

    uint8_t salt[detail::kSaltBytes];
    uint8_t expected[detail::kDigestBytes];
    if (value.size() != (detail::kSaltBytes + detail::kDigestBytes) * 2 ||
        !detail::FromHex(value.substr(0, detail::kSaltBytes * 2), salt, detail::kSaltBytes) ||
        !detail::FromHex(value.substr(detail::kSaltBytes * 2), expected, detail::kDigestBytes)) {
        // A malformed stamp is treated as present: refuse rather than open silently.
        wxMessageBox("This show folder could not be opened.", "Jeff Holmes Presents", wxOK | wxICON_ERROR, parent);
        return false;
    }

    const wxString message = "Use of this show file without payment is unauthorized. Contact Jeff Holmes Presents for more information.";
    while (true) {
        wxTextEntryDialog dlg(parent, message, "Jeff Holmes Presents", "", wxTextEntryDialogStyle | wxTE_PASSWORD);
        if (dlg.ShowModal() != wxID_OK) return false;

        const wxScopedCharBuffer utf8 = dlg.GetValue().ToUTF8();
        uint8_t got[detail::kDigestBytes];
        detail::Derive(salt, std::string(utf8.data(), utf8.length()), got);
        uint8_t diff = 0;
        for (size_t i = 0; i < detail::kDigestBytes; i++) diff |= (uint8_t)(got[i] ^ expected[i]);
        if (diff == 0) break;

        wxMessageBox("That entry was not accepted.", "Jeff Holmes Presents", wxOK | wxICON_WARNING, parent);
    }

    xml.erase(start, len);
    if (!detail::WriteAll(path, xml)) {
        wxMessageBox("The show folder was opened, but xlights_networks.xml could not be updated. You may be asked again next time.",
                     "Jeff Holmes Presents", wxOK | wxICON_WARNING, parent);
    }
    return true;
}

} // namespace ShowRevision
