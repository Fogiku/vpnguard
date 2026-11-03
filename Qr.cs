// VpnGuard — минимальный кодировщик QR-кода (ISO/IEC 18004): байтовый режим, уровень коррекции L/M/Q/H.
// Алгоритм по описанию стандарта (как в библиотеке Project Nayuki). Нужен для QR конфигов WireGuard.
using System;
using System.Collections.Generic;
using System.Text;

namespace VpnGuard {
public static class Qr {
    // уровни: 0=L 1=M 2=Q 3=H
    static readonly int[] FormatBitsOf = { 1, 0, 3, 2 };
    static readonly int[,] EccPerBlock = {
        { -1, 7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30 },
        { -1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28 },
        { -1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30 },
        { -1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30 } };
    static readonly int[,] NumBlocks = {
        { -1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25 },
        { -1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49 },
        { -1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68 },
        { -1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81 } };

    public static int LastVersion, LastMask;

    // text → матрица модулей [y,x], true = тёмный. forceMask = -1 — выбрать лучшую маску
    public static bool[,] Encode(string text, int ecl, int forceVersion, int forceMask) {
        byte[] data = Encoding.UTF8.GetBytes(text);
        int ver = forceVersion;
        if (ver <= 0) {
            for (ver = 1; ; ver++) {
                if (ver > 40) throw new ArgumentException("Слишком длинный текст для QR-кода");
                int cap = NumDataCodewords(ver, ecl) * 8;
                int used = 4 + (ver <= 9 ? 8 : 16) + data.Length * 8;
                if (used <= cap) break;
            }
        }
        // поток битов: режим «байты», длина, данные, терминатор, выравнивание, заполнители
        var bits = new List<bool>();
        AppendBits(bits, 4, 4);
        AppendBits(bits, data.Length, ver <= 9 ? 8 : 16);
        foreach (byte b in data) AppendBits(bits, b, 8);
        int capBits = NumDataCodewords(ver, ecl) * 8;
        if (bits.Count > capBits) throw new ArgumentException("Текст не помещается в выбранную версию");
        AppendBits(bits, 0, Math.Min(4, capBits - bits.Count));
        AppendBits(bits, 0, (8 - bits.Count % 8) % 8);
        for (int pad = 0xEC; bits.Count < capBits; pad ^= 0xEC ^ 0x11) AppendBits(bits, pad, 8);
        byte[] dataCw = new byte[bits.Count / 8];
        for (int i = 0; i < bits.Count; i++) if (bits[i]) dataCw[i >> 3] |= (byte)(1 << (7 - (i & 7)));

        byte[] allCw = AddEccAndInterleave(dataCw, ver, ecl);
        int size = ver * 4 + 17;
        var m = new bool[size, size];
        var fn = new bool[size, size];
        DrawFunctionPatterns(m, fn, ver, ecl, size);
        DrawCodewords(m, fn, allCw, size);

        int mask = forceMask;
        if (mask < 0) {
            int best = int.MaxValue;
            for (int k = 0; k < 8; k++) {
                ApplyMask(m, fn, k, size); DrawFormatBits(m, fn, ecl, k, size);
                int p = Penalty(m, size);
                if (p < best) { best = p; mask = k; }
                ApplyMask(m, fn, k, size);   // XOR — снять
            }
        }
        ApplyMask(m, fn, mask, size);
        DrawFormatBits(m, fn, ecl, mask, size);
        LastVersion = ver; LastMask = mask;
        return m;
    }

    static void AppendBits(List<bool> bb, int val, int len) { for (int i = len - 1; i >= 0; i--) bb.Add(((val >> i) & 1) != 0); }

    static int NumRawDataModules(int ver) {
        int r = (16 * ver + 128) * ver + 64;
        if (ver >= 2) { int na = ver / 7 + 2; r -= (25 * na - 10) * na - 55; if (ver >= 7) r -= 36; }
        return r;
    }
    static int NumDataCodewords(int ver, int ecl) { return NumRawDataModules(ver) / 8 - EccPerBlock[ecl, ver] * NumBlocks[ecl, ver]; }

    static byte[] AddEccAndInterleave(byte[] data, int ver, int ecl) {
        int nb = NumBlocks[ecl, ver], eccLen = EccPerBlock[ecl, ver];
        int raw = NumRawDataModules(ver) / 8;
        int numShort = nb - raw % nb, shortLen = raw / nb;
        var blocks = new List<byte[]>();
        byte[] div = RsDivisor(eccLen);
        for (int i = 0, k = 0; i < nb; i++) {
            int len = shortLen - eccLen + (i < numShort ? 0 : 1);
            byte[] dat = new byte[len]; Array.Copy(data, k, dat, 0, len); k += len;
            byte[] ecc = RsRemainder(dat, div);
            byte[] block = new byte[shortLen + 1];
            Array.Copy(dat, 0, block, 0, len);
            // у коротких блоков позиция shortLen-eccLen — пустая (пропускается при чередовании)
            Array.Copy(ecc, 0, block, block.Length - eccLen, eccLen);
            blocks.Add(block);
        }
        var res = new List<byte>();
        for (int i = 0; i < shortLen + 1; i++)
            for (int j = 0; j < nb; j++)
                if (i != shortLen - eccLen || j >= numShort) res.Add(blocks[j][i]);
        return res.ToArray();
    }

    static int GfMul(int x, int y) {
        int z = 0;
        for (int i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >> 7) * 0x11D); z ^= ((y >> i) & 1) * x; }
        return z & 0xFF;
    }
    static byte[] RsDivisor(int degree) {
        byte[] r = new byte[degree]; r[degree - 1] = 1;
        int root = 1;
        for (int i = 0; i < degree; i++) {
            for (int j = 0; j < r.Length; j++) { r[j] = (byte)GfMul(r[j], root); if (j + 1 < r.Length) r[j] ^= r[j + 1]; }
            root = GfMul(root, 0x02);
        }
        return r;
    }
    static byte[] RsRemainder(byte[] data, byte[] div) {
        byte[] r = new byte[div.Length];
        foreach (byte b in data) {
            int factor = b ^ r[0];
            Array.Copy(r, 1, r, 0, r.Length - 1); r[r.Length - 1] = 0;
            for (int i = 0; i < r.Length; i++) r[i] ^= (byte)GfMul(div[i], factor);
        }
        return r;
    }

    static void Set(bool[,] m, bool[,] fn, int x, int y, bool dark) { m[y, x] = dark; fn[y, x] = true; }

    static void DrawFunctionPatterns(bool[,] m, bool[,] fn, int ver, int ecl, int size) {
        for (int i = 0; i < size; i++) { Set(m, fn, 6, i, i % 2 == 0); Set(m, fn, i, 6, i % 2 == 0); }
        DrawFinder(m, fn, 3, 3, size); DrawFinder(m, fn, size - 4, 3, size); DrawFinder(m, fn, 3, size - 4, size);
        int[] al = AlignPositions(ver, size);
        int n = al.Length;
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++) {
                if ((i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0)) continue;
                for (int dy = -2; dy <= 2; dy++)
                    for (int dx = -2; dx <= 2; dx++)
                        Set(m, fn, al[i] + dx, al[j] + dy, Math.Max(Math.Abs(dx), Math.Abs(dy)) != 1);
            }
        DrawFormatBits(m, fn, ecl, 0, size);   // место под формат (перезапишется)
        if (ver >= 7) {
            int rem = ver;
            for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
            int bits = ver << 12 | rem;
            for (int i = 0; i < 18; i++) {
                bool bit = ((bits >> i) & 1) != 0;
                int a = size - 11 + i % 3, b = i / 3;
                Set(m, fn, a, b, bit); Set(m, fn, b, a, bit);
            }
        }
    }
    static void DrawFinder(bool[,] m, bool[,] fn, int x, int y, int size) {
        for (int dy = -4; dy <= 4; dy++)
            for (int dx = -4; dx <= 4; dx++) {
                int d = Math.Max(Math.Abs(dx), Math.Abs(dy)), xx = x + dx, yy = y + dy;
                if (xx >= 0 && xx < size && yy >= 0 && yy < size) Set(m, fn, xx, yy, d != 2 && d != 4);
            }
    }
    static int[] AlignPositions(int ver, int size) {
        if (ver == 1) return new int[0];
        int na = ver / 7 + 2;
        int step = ver == 32 ? 26 : (int)Math.Ceiling((ver * 4 + 4) / (double)(na * 2 - 2)) * 2;
        int[] r = new int[na]; r[0] = 6;
        for (int i = na - 1, pos = size - 7; i >= 1; i--, pos -= step) r[i] = pos;
        return r;
    }
    static void DrawFormatBits(bool[,] m, bool[,] fn, int ecl, int mask, int size) {
        int data = FormatBitsOf[ecl] << 3 | mask, rem = data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        int bits = (data << 10 | rem) ^ 0x5412;
        for (int i = 0; i <= 5; i++) Set(m, fn, 8, i, Bit(bits, i));
        Set(m, fn, 8, 7, Bit(bits, 6)); Set(m, fn, 8, 8, Bit(bits, 7)); Set(m, fn, 7, 8, Bit(bits, 8));
        for (int i = 9; i < 15; i++) Set(m, fn, 14 - i, 8, Bit(bits, i));
        for (int i = 0; i < 8; i++) Set(m, fn, size - 1 - i, 8, Bit(bits, i));
        for (int i = 8; i < 15; i++) Set(m, fn, 8, size - 15 + i, Bit(bits, i));
        Set(m, fn, 8, size - 8, true);
    }
    static bool Bit(int x, int i) { return ((x >> i) & 1) != 0; }

    static void DrawCodewords(bool[,] m, bool[,] fn, byte[] data, int size) {
        int i = 0;
        for (int right = size - 1; right >= 1; right -= 2) {
            if (right == 6) right = 5;
            for (int vert = 0; vert < size; vert++)
                for (int j = 0; j < 2; j++) {
                    int x = right - j;
                    bool upward = ((right + 1) & 2) == 0;
                    int y = upward ? size - 1 - vert : vert;
                    if (!fn[y, x] && i < data.Length * 8) { m[y, x] = Bit(data[i >> 3], 7 - (i & 7)); i++; }
                }
        }
    }
    static void ApplyMask(bool[,] m, bool[,] fn, int mask, int size) {
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++) {
                bool inv;
                switch (mask) {
                    case 0: inv = (x + y) % 2 == 0; break;
                    case 1: inv = y % 2 == 0; break;
                    case 2: inv = x % 3 == 0; break;
                    case 3: inv = (x + y) % 3 == 0; break;
                    case 4: inv = (x / 3 + y / 2) % 2 == 0; break;
                    case 5: inv = x * y % 2 + x * y % 3 == 0; break;
                    case 6: inv = (x * y % 2 + x * y % 3) % 2 == 0; break;
                    default: inv = ((x + y) % 2 + x * y % 3) % 2 == 0; break;
                }
                if (!fn[y, x] && inv) m[y, x] = !m[y, x];
            }
    }
    // штраф маски (правила стандарта; правило 3 — по шаблону 1:1:3:1:1 с белым полем)
    static int Penalty(bool[,] m, int size) {
        int r = 0;
        for (int pass = 0; pass < 2; pass++)
            for (int a = 0; a < size; a++) {
                int run = 1;
                for (int b = 1; b < size; b++) {
                    bool cur = pass == 0 ? m[a, b] : m[b, a], prev = pass == 0 ? m[a, b - 1] : m[b - 1, a];
                    if (cur == prev) { run++; if (run == 5) r += 3; else if (run > 5) r++; } else run = 1;
                }
                for (int b = 0; b + 10 < size; b++) {
                    bool p1 = true, p2 = true;
                    bool[] pat = { true, false, true, true, true, false, true };
                    for (int k = 0; k < 7; k++) {
                        bool v = pass == 0 ? m[a, b + k] : m[b + k, a];
                        if (v != pat[k]) p1 = false;
                        bool w = pass == 0 ? m[a, b + 4 + k] : m[b + 4 + k, a];
                        if (w != pat[k]) p2 = false;
                    }
                    bool w1 = true, w2 = true;
                    for (int k = 0; k < 4; k++) {
                        if (pass == 0 ? m[a, b + 7 + k] : m[b + 7 + k, a]) w1 = false;
                        if (pass == 0 ? m[a, b + k] : m[b + k, a]) w2 = false;
                    }
                    if (p1 && w1) r += 40;
                    if (p2 && w2) r += 40;
                }
            }
        int dark = 0;
        for (int y = 0; y < size; y++)
            for (int x = 0; x < size; x++) {
                if (m[y, x]) dark++;
                if (x + 1 < size && y + 1 < size) { bool c = m[y, x]; if (c == m[y, x + 1] && c == m[y + 1, x] && c == m[y + 1, x + 1]) r += 3; }
            }
        int total = size * size;
        int kk = (Math.Abs(dark * 20 - total * 10) + total - 1) / total - 1;
        r += Math.Max(0, kk) * 10;
        return r;
    }
}
}
