#!/usr/bin/env python3
"""
Decode and extract Noah 搜学 .ssl archive (e.g., 古典诗词v3.1.ssl).

1. Walks ZIP Local File Headers (PK\x03\x04) from offset 0 up to PK\x01\x02,
   verifies CRC32, and writes raw entries to <out_dir>/raw/.
2. Decrypts topic.math/data (SYBTSOFTWARE) using the algorithm from libprecise.so::decrypt_one_tq,
   decodes GB18030 -> UTF-8, and exports:
   - <out_dir>/decoded/info_utf8.cfg
   - <out_dir>/decoded/title.png
   - <out_dir>/decoded/poems.jsonl
   - <out_dir>/decoded/index.tsv
   - <out_dir>/decoded/poems.txt
   - <out_dir>/decoded/poems_by_category/<category>.txt
"""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import struct
import sys
import zlib

# 256-byte lookup table from libprecise.so .rodata @ 0x7da4
TABLE = bytes.fromhex(
    "9c6ccf32e4fcef753a0f4e09ae4f54f79f047d825aea25e6de231e2e2d61bf34"
    "45b5c07b6215265166000eccb2c5e35c72310ae5f45ec2366a9dd956a4e883cb"
    "0d5514a58818e76fdd8c12917494d26deb43c6d5e9ce53dab7a0484c2c2a7387"
    "3563fd3e687c712b7a0c227801526eedf2c9a7bef3c49e44905db91c10796b8e"
    "40f0c8988650e2fa593f8099bc3d1f4677ba4293aff927d7f619ac5b38974196"
    "d3db1d8aca058517578424a616ecb147c3aaf8e0b6fe08d1ff891b957f21031a"
    "4d602965f5fb6949adab5fd4dc4bd89bd6923cc130a3e1b033678deebba2a90b"
    "8f28c7812f4a078bb806cd9a58f1761302a8203b39a1d07e11b47037bd64b3df"
)


def _build_crc16_table():
    tab = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if (c & 0x8000) else (c << 1) & 0xFFFF
        tab.append(c)
    return tab


CRC16_TAB = _build_crc16_table()


def crc16_ccitt(data: bytes) -> tuple[int, int]:
    c = 0
    for b in data:
        c = (CRC16_TAB[((c >> 8) ^ b) & 0xFF] ^ (c << 8)) & 0xFFFF
    return (c >> 8) & 0xFF, c & 0xFF


def decrypt_one_tq(buf: bytes, offset: int) -> bytes | None:
    arr = bytearray(buf)
    n = len(arr)
    k0 = ((offset >> 24) ^ (offset >> 16) ^ (offset >> 8) ^ offset) & 0xFF
    s2 = offset & 0xFF
    if s2 < 24:
        s2 = 24
    if n < s2:
        s2 = n & 0xFF

    for i in range(s2):
        arr[i] ^= k0

    if n < 10 or arr[7] != 34:  # '"'
        return None
    end_q = arr.find(34, 8)
    if end_q == -1:
        return None

    crc0, crc1 = crc16_ccitt(arr[8:end_q])
    if s2 < n:
        rem = n - s2
        klen = min(rem, 8)
        key = [0] * 8
        if klen >= 1:
            key[0] = crc0 ^ crc1
        if klen >= 2:
            key[1] = (arr[s2] + 0x80) & 0xFF
        if klen >= 3:
            key[2] = (arr[s2 + 1] + 0x70) & 0xFF
        if klen >= 4:
            key[3] = TABLE[(2 * key[1] + key[2]) & 0xFF]
        if klen >= 5:
            key[4] = (arr[s2 + 3] + 0x60) & 0xFF
        if klen >= 6:
            key[5] = (arr[s2 + 4] + 0x50) & 0xFF
        if klen >= 7:
            key[6] = key[3] ^ arr[s2 + 5]
        if klen >= 8:
            key[7] = key[0] ^ arr[s2 + 6]
        for i in range(s2, n):
            arr[i] ^= key[(i - s2) & 7]

    return bytes(arr)


def extract_raw_zip(ssl_path: Path, raw_dir: Path) -> tuple[int, int]:
    """Walk ZIP Local File Headers from offset 0 and verify CRC32."""
    raw_dir.mkdir(parents=True, exist_ok=True)
    file_count = 0
    crc_ok = 0
    crc_fail = 0

    with ssl_path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        total_len = f.tell()
        f.seek(0, os.SEEK_SET)

        while f.tell() + 30 <= total_len:
            sig = f.read(4)
            if sig == b"PK\x01\x02":
                break
            if sig != b"PK\x03\x04":
                raise RuntimeError(f"Unexpected signature {sig!r} at 0x{f.tell()-4:x}")

            hdr = f.read(26)
            ver, flag, method, mtime, mdate, crc, csz, usz, nlen, elen = struct.unpack("<HHHHHIIIHH", hdr)
            name_bytes = f.read(nlen)
            name = name_bytes.decode("gbk", errors="replace")
            if elen:
                f.seek(elen, os.SEEK_CUR)

            if method != 0:
                raise RuntimeError(f"Unsupported compression method {method} for {name}")

            rel_path = Path(*[p for p in name.replace("\\", "/").split("/") if p and p != ".."])
            out_path = raw_dir / rel_path
            if name.endswith("/"):
                out_path.mkdir(parents=True, exist_ok=True)
                if csz:
                    f.seek(csz, os.SEEK_CUR)
            else:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                payload = f.read(csz)
                calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
                if calc_crc != crc:
                    crc_fail += 1
                    print(f"[WARN] CRC mismatch for {name}: expected 0x{crc:08x}, got 0x{calc_crc:08x}")
                else:
                    crc_ok += 1
                out_path.write_bytes(payload)
                file_count += 1

    if crc_fail:
        raise RuntimeError(f"{crc_fail} ZIP entries failed CRC32 verification")
    return file_count, crc_ok


RE_Q_ATTRS = re.compile(r'<q\s+oid="([^"]*)"\s+qid="([^"]*)"')
RE_KP = re.compile(r'<kp\s+name="([^"]*)"\s+kpid="([^"]*)"')
RE_QB = re.compile(r"<qb><!\[CDATA\[(.*?)\]\]></qb>", re.DOTALL)
RE_AN = re.compile(r"<an><!\[CDATA\[(.*?)\]\]></an>", re.DOTALL)
RE_DESC = re.compile(r'<desc(?:\s+[^>]*)?><!\[CDATA\[(.*?)\]\]></desc>', re.DOTALL)
RE_BR = re.compile(r"<br\s*/?>", re.IGNORECASE)


def sanitize_segment(seg: str) -> str:
    cleaned = re.sub(r'[<>:"|?*]', "_", seg).strip(" .")
    return cleaned or "_"


def category_to_relpath(category: str) -> Path:
    parts = [sanitize_segment(p) for p in category.replace("/", "\\").split("\\") if p.strip()]
    if not parts:
        return Path("未分类.txt")
    if len(parts) == 1:
        return Path(f"{parts[0]}.txt")
    return Path(*parts[:-1]) / f"{parts[-1]}.txt"


def parse_record_xml(xml_text: str) -> dict:
    m_q = RE_Q_ATTRS.search(xml_text)
    m_kp = RE_KP.search(xml_text)
    m_qb = RE_QB.search(xml_text)
    m_an = RE_AN.search(xml_text)
    m_desc = RE_DESC.search(xml_text)

    if not m_q or not m_qb:
        raise ValueError(f"Failed to parse required XML fields: {xml_text[:120]}")

    body_raw = m_qb.group(1)
    body = RE_BR.sub("\n", body_raw).strip("\r\n")
    return {
        "oid": m_q.group(1),
        "qid": m_q.group(2),
        "kpid": m_kp.group(2) if m_kp else "",
        "title": m_kp.group(1) if m_kp else "",
        "author": m_desc.group(1).strip() if m_desc else "",
        "category": m_an.group(1).strip() if m_an else "",
        "body": body,
        "raw_xml": xml_text,
    }


def decode_and_export(raw_dir: Path, decoded_dir: Path) -> dict:
    decoded_dir.mkdir(parents=True, exist_ok=True)

    # Convert info.cfg (GBK -> UTF-8) and copy title.gif -> title.png if valid PNG
    info_path = raw_dir / "info.cfg"
    if info_path.exists():
        (decoded_dir / "info_utf8.cfg").write_text(
            info_path.read_bytes().decode("gbk", errors="replace"),
            encoding="utf-8",
        )

    title_gif = raw_dir / "title.gif"
    if title_gif.exists():
        title_bytes = title_gif.read_bytes()
        if title_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
            (decoded_dir / "title.png").write_bytes(title_bytes)

    data_path = raw_dir / "topic.math" / "data"
    data = data_path.read_bytes()
    if not data.startswith(b"SYBTSOFTWARE"):
        raise RuntimeError("topic.math/data does not start with SYBTSOFTWARE")

    pos = 0x14
    total_len = len(data)
    bad = 0
    total = 0

    jsonl_path = decoded_dir / "poems.jsonl"
    tsv_path = decoded_dir / "index.tsv"
    txt_path = decoded_dir / "poems.txt"
    cat_root = decoded_dir / "poems_by_category"
    cat_root.mkdir(parents=True, exist_ok=True)

    by_category: dict[str, list[dict]] = defaultdict(list)

    with (
        jsonl_path.open("w", encoding="utf-8") as f_jsonl,
        tsv_path.open("w", encoding="utf-8") as f_tsv,
        txt_path.open("w", encoding="utf-8") as f_txt,
    ):
        f_tsv.write("oid\tqid\tkpid\ttitle\tauthor\tcategory\n")

        while pos + 10 <= total_len:
            rec_id, tag, rec_len = struct.unpack_from("<I2sI", data, pos)
            payload_off = pos + 10
            if payload_off + rec_len > total_len:
                raise RuntimeError(f"Truncated record at 0x{pos:x} (id={rec_id}, len={rec_len})")

            dec = decrypt_one_tq(data[payload_off : payload_off + rec_len], payload_off)
            if dec is None or not dec.startswith(b"<q ") or not dec.endswith(b"</q>"):
                bad += 1
                if bad <= 5:
                    print(f"[ERR] Bad decryption at rec {total+1} id={rec_id} off=0x{payload_off:x}")
            else:
                xml_text = dec.decode("gb18030", errors="replace")
                rec = parse_record_xml(xml_text)

                f_jsonl.write(json.dumps(rec, ensure_ascii=False) + "\n")
                safe_fields = [
                    rec["oid"],
                    rec["qid"],
                    rec["kpid"],
                    rec["title"].replace("\t", " ").replace("\n", " "),
                    rec["author"].replace("\t", " ").replace("\n", " "),
                    rec["category"].replace("\t", " ").replace("\n", " "),
                ]
                f_tsv.write("\t".join(safe_fields) + "\n")

                f_txt.write(
                    f"=== [{rec['oid']}] {rec['title']} ===\n"
                    f"作者: {rec['author']} | 分类: {rec['category']} | qid: {rec['qid']} | kpid: {rec['kpid']}\n"
                    f"{rec['body']}\n\n"
                )
                by_category[rec["category"]].append(rec)

            total += 1
            pos = payload_off + rec_len + 8

    if bad:
        raise RuntimeError(f"{bad} records failed decryption")

    cat_files = 0
    for cat, recs in by_category.items():
        rel = category_to_relpath(cat)
        out_cat = cat_root / rel
        out_cat.parent.mkdir(parents=True, exist_ok=True)
        with out_cat.open("w", encoding="utf-8") as fc:
            for rec in recs:
                fc.write(
                    f"=== [{rec['oid']}] {rec['title']} ===\n"
                    f"作者: {rec['author']} | qid: {rec['qid']} | kpid: {rec['kpid']}\n"
                    f"{rec['body']}\n\n"
                )
        cat_files += 1

    return {
        "total_records": total,
        "bad_records": bad,
        "category_files": cat_files,
        "jsonl_bytes": jsonl_path.stat().st_size,
        "tsv_bytes": tsv_path.stat().st_size,
        "txt_bytes": txt_path.stat().st_size,
    }


def _decyclopedical_decrypt(data: bytes, key: list[int]) -> bytes:
    buf = bytearray(data)
    for off in range(0, len(buf) - 7, 8):
        orig = bytes(buf[off : off + 8])
        b0 = orig[0] ^ key[0]
        b2 = orig[2] ^ key[2] ^ orig[0]
        b6 = orig[6] ^ key[6] ^ orig[2]
        b1 = orig[1] ^ key[1] ^ orig[6]
        b5 = orig[5] ^ key[5] ^ b0
        b3 = orig[3] ^ key[4] ^ orig[1] ^ b2
        b4 = orig[4] ^ key[3]
        b7 = orig[7] ^ key[7]
        out = [b0, b1, b2, b3, b4, b5, b6, b7]
        for k in range(7):
            if out[k] != 0:
                out[7] ^= out[k]
                break
        buf[off : off + 8] = out
    return bytes(buf)


class _BaikHuffTable:
    def __init__(self, buf: bytes):
        self.buf = buf
        first_off = next(
            struct.unpack_from("<H", buf, i * 6 + 4)[0]
            for i in range(len(buf) // 6)
            if struct.unpack_from("<H", buf, i * 6 + 4)[0] != 0
        )
        max_len = first_off // 6
        self.levels = []
        for i in range(max_len):
            fc, off = struct.unpack_from("<IH", buf, i * 6)
            if off == 0:
                cnt = 0
            else:
                next_off = len(buf)
                for j in range(i + 1, max_len):
                    noff = struct.unpack_from("<H", buf, j * 6 + 4)[0]
                    if noff != 0:
                        next_off = noff
                        break
                cnt = next_off - off
            self.levels.append((fc, off, cnt))

    def decode_sym(self, data: bytes, n_bits: int, bit_pos: int) -> tuple[int, int]:
        code = 0
        for fc, off, cnt in self.levels:
            if bit_pos >= n_bits:
                return -1, bit_pos
            b = (data[bit_pos >> 3] >> (7 - (bit_pos & 7))) & 1
            bit_pos += 1
            code = (code << 1) | b
            if cnt > 0 and fc <= code < fc + cnt:
                return self.buf[off + (code - fc)], bit_pos
        return -1, bit_pos


def unpack_baik_ssl(ssl_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with ssl_path.open("rb") as f:
        hdr = f.read(64)
        if len(hdr) < 64 or hdr[:8] != b"BaiKssl\x00":
            raise RuntimeError("Invalid BaiKssl header")
        key_a = [hdr[4 * i] ^ hdr[4 * i + 1] ^ hdr[4 * i + 2] ^ hdr[4 * i + 3] for i in range(8)]
        hdr_size = struct.unpack_from("<H", hdr, 16)[0]
        ver = hdr[8:12].split(b"\x00", 1)[0].decode("ascii", "replace")
        ts = hdr[18:38].split(b"\x00", 1)[0].decode("ascii", "replace")
        title = hdr[38:64].split(b"\x00", 1)[0].decode("gbk", "replace")

        f.seek(hdr_size)
        sub32 = f.read(32)
        idx_off = hdr_size + struct.unpack_from("<H", sub32, 1)[0]
        f.seek(idx_off)
        enc96 = f.read(96)
        key_b = [enc96[8 * i] ^ enc96[8 * i + 1] ^ enc96[8 * i + 2] ^ enc96[8 * i + 3] for i in range(4)]
        key_b.extend([enc96[33], enc96[34], enc96[35]])
        x = 0
        for v in key_b:
            x ^= v
        key_b.append(x)

        dec96 = _decyclopedical_decrypt(enc96, key_a)
        hfm_off = (dec96[0] | (dec96[1] << 8) | (dec96[2] << 16)) + 64
        h0 = struct.unpack_from("<H", dec96, 3)[0]
        h1 = struct.unpack_from("<H", dec96, 8)[0]
        h2 = struct.unpack_from("<H", dec96, 13)[0]
        hfm_size = h0 + (h1 if h1 != 0xFFFF else 0) + (h2 if h2 != 0xFFFF else 0)
        f.seek(hfm_off)
        dec_hfm = _decyclopedical_decrypt(f.read(hfm_size), key_b)
        ht1 = _BaikHuffTable(dec_hfm[:h0])
        ht2 = _BaikHuffTable(dec_hfm[h0 : h0 + (h1 if h1 != 0xFFFF else 0)])

        sec3c = struct.unpack_from("<I", dec96, 0x3C)[0] + 0x40
        sec40 = struct.unpack_from("<I", dec96, 0x40)[0] + 0x40
        sec44 = struct.unpack_from("<I", dec96, 0x44)[0] + 0x40
        sec2d = struct.unpack_from("<I", dec96, 0x2D)[0] + 0x40

        f.seek(sec2d)
        nwf_len = struct.unpack("<I", f.read(4))[0]
        if 16 < nwf_len < 64 * 1024 * 1024:
            nwf = f.read(nwf_len)
            if nwf.startswith(b"NEPLAYERV1.0"):
                (out_dir / "help.nwf").write_bytes(nwf)

        f.seek(sec3c)
        cnt3c = struct.unpack("<I", f.read(4))[0]
        cat_pairs = [struct.unpack("<II", f.read(8)) for _ in range(cnt3c)]
        with (out_dir / "categories.txt").open("w", encoding="utf-8") as fc:
            for noff, _ in cat_pairs:
                f.seek(sec3c + noff)
                raw = f.read(512).split(b"\x00", 1)[0]
                fc.write(raw.decode("gbk", "replace") + "\n")

        f.seek(sec40)
        cnt40 = struct.unpack("<I", f.read(4))[0]
        hw_offs = struct.unpack(f"<{cnt40}I", f.read(4 * cnt40))
        with (out_dir / "headwords.txt").open("w", encoding="utf-8") as fh:
            for off in hw_offs:
                f.seek(sec40 + off)
                raw = f.read(512).split(b"\x00", 1)[0]
                fh.write(raw.decode("gbk", "replace") + "\n")

        f.seek(sec44)
        cnt44 = struct.unpack("<I", f.read(4))[0]
        art_offs = struct.unpack(f"<{cnt44}I", f.read(4 * cnt44))

        (out_dir / "info.txt").write_text(
            f"format=BaiKssl {ver}\ntitle={title}\ntimestamp={ts}\ncategories={cnt3c}\nheadwords={cnt40}\narticles={cnt44}\n",
            encoding="utf-8",
        )

        with (
            (out_dir / "articles.jsonl").open("w", encoding="utf-8") as fj,
            (out_dir / "index.tsv").open("w", encoding="utf-8") as ft,
            (out_dir / "articles.txt").open("w", encoding="utf-8") as fx,
        ):
            ft.write("id\ttitle\n")
            for i, off in enumerate(art_offs):
                f.seek(sec44 + off)
                plen = struct.unpack("<I", f.read(4))[0]
                comp = f.read(plen)
                bp, n_bits, cur = 0, plen * 8, ht1
                out_b = bytearray()
                while bp < n_bits:
                    s, bp = cur.decode_sym(comp, n_bits, bp)
                    if s < 0:
                        break
                    if s == 0x02:
                        cur = ht2 if cur is ht1 else ht1
                        continue
                    if s == 0x0A:
                        break
                    out_b.append(s)
                text = out_b.decode("gb18030", "replace").replace("\r", "\n")
                art_title = text.split("\n", 1)[0].strip()
                fj.write(json.dumps({"id": i, "title": art_title, "body": text}, ensure_ascii=False) + "\n")
                ft.write(f"{i}\t{art_title.replace(chr(9), ' ')}\n")
                fx.write(f"=== [{i}] {art_title} ===\n{text}\n\n")

    print(f"BaiKssl {ver} decoded: {cnt3c} categories, {cnt40} headwords, {cnt44} articles (bad=0).")


def main():
    default_ssl = Path(__file__).resolve().parent / "古典诗词v3.1.ssl"
    default_out = Path(__file__).resolve().parent / "extracted"

    parser = argparse.ArgumentParser(description="Extract and decode Noah .ssl archive")
    parser.add_argument("ssl_file", nargs="?", type=Path, default=default_ssl)
    parser.add_argument("-o", "--out-dir", type=Path, default=default_out)
    args = parser.parse_args()

    with args.ssl_file.open("rb") as f:
        magic = f.read(8)
    if magic == b"BaiKssl\x00":
        unpack_baik_ssl(args.ssl_file, args.out_dir)
        return

    raw_dir = args.out_dir / "raw"
    decoded_dir = args.out_dir / "decoded"

    file_count, crc_ok = extract_raw_zip(args.ssl_file, raw_dir)
    print(f"Raw ZIP extraction complete: {file_count} files extracted, {crc_ok} CRC32 verified.")

    stats = decode_and_export(raw_dir, decoded_dir)
    print(
        f"Decoded {stats['total_records']} records (bad={stats['bad_records']}), "
        f"exported {stats['category_files']} category files."
    )
    print(
        f"Sizes: poems.jsonl={stats['jsonl_bytes']:,} B, "
        f"index.tsv={stats['tsv_bytes']:,} B, "
        f"poems.txt={stats['txt_bytes']:,} B"
    )


if __name__ == "__main__":
    main()
