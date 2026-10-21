import hashlib, io, json, mmap, os, struct, sys

ALIGN = 512                  # real file starts sit on sector boundaries
MAX_SIZE = 64 * 1024 * 1024  # never carve more than this per file


# ---- each function returns the end offset of the file starting at pos, or None ----

def jpg_end(d, pos):
    """Walk JPEG segments; embedded EXIF thumbnails are skipped, not mistaken for the end."""
    n, lim = len(d), min(len(d), pos + MAX_SIZE)
    i = pos + 2
    while i + 2 <= lim:
        if d[i] != 0xFF:
            return None
        m = d[i + 1]
        if m == 0xFF:
            i += 1
        elif m == 0xD9:
            return i + 2
        elif m == 0x01 or 0xD0 <= m <= 0xD7:
            i += 2
        else:
            i += 2 + struct.unpack_from(">H", d, i + 2)[0]
            if m == 0xDA:  # compressed image data: skip to the next real marker
                while True:
                    j = d.find(b"\xff", i, lim)
                    if j == -1 or j + 1 >= lim:
                        return None
                    nxt = d[j + 1]
                    if nxt == 0xFF:
                        i = j + 1
                    elif nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                        i = j + 2
                    else:
                        i = j
                        break
    return None


def png_end(d, pos):
    """Walk PNG chunks until IEND."""
    n, i = len(d), pos + 8
    while i + 12 <= n and i - pos < MAX_SIZE:
        length = struct.unpack_from(">I", d, i)[0]
        kind = bytes(d[i + 4:i + 8])
        i += 12 + length
        if kind == b"IEND":
            return i
    return None


def gif_end(d, pos):
    """Walk GIF blocks until the trailer byte."""
    n = len(d)

    def skip_sub(i):
        while i < n:
            ln = d[i]
            i += 1
            if ln == 0:
                return i
            i += ln
        return None

    flags = d[pos + 10]
    i = pos + 13
    if flags & 0x80:
        i += 3 * (2 ** ((flags & 7) + 1))
    while i is not None and i < n and i - pos < MAX_SIZE:
        b = d[i]
        if b == 0x3B:
            return i + 1
        if b == 0x21:
            i = skip_sub(i + 2)
        elif b == 0x2C:
            lf = d[i + 9]
            i += 10
            if lf & 0x80:
                i += 3 * (2 ** ((lf & 7) + 1))
            i = skip_sub(i + 1)
        else:
            return None
    return None


def bmp_end(d, pos):
    size = struct.unpack_from("<I", d, pos + 2)[0]
    dib = struct.unpack_from("<I", d, pos + 14)[0]
    ok = bytes(d[pos + 6:pos + 10]) == b"\0\0\0\0" and dib in (12, 40, 108, 124)
    return pos + size if ok and 100 < size < MAX_SIZE and pos + size <= len(d) else None


TIFF_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8}


def tif_end(d, pos):
    """Read the TIFF directory: the file ends after its last strip/tile or value block."""
    n = len(d)
    e = "<" if d[pos] == 0x49 else ">"
    ifd = struct.unpack_from(e + "I", d, pos + 4)[0]
    end = pos + 8
    for _ in range(16):
        if not ifd:
            break
        a = pos + ifd
        count = struct.unpack_from(e + "H", d, a)[0]
        if count == 0 or count > 512 or a + 2 + count * 12 + 4 > n:
            return None
        end = max(end, a + 2 + count * 12 + 4)
        vals = {}
        for k in range(count):
            o = a + 2 + k * 12
            tag, typ, c = struct.unpack_from(e + "HHI", d, o)
            size = TIFF_TYPE_SIZE.get(typ)
            if not size:
                return None
            total = size * c
            data_at = o + 8
            if total > 4:
                data_at = pos + struct.unpack_from(e + "I", d, o + 8)[0]
                end = max(end, data_at + total)
            if tag in (273, 279, 324, 325) and typ in (3, 4) and c <= 200000:
                vals[tag] = struct.unpack_from(e + f"{c}{'H' if typ == 3 else 'I'}", d, data_at)
        offs = vals.get(273) or vals.get(324)
        cnts = vals.get(279) or vals.get(325)
        if offs and cnts:
            for off, cnt in zip(offs, cnts):
                end = max(end, pos + off + cnt)
        ifd = struct.unpack_from(e + "I", d, a + 2 + count * 12)[0]
    return end if end <= n and end - pos < MAX_SIZE else None


def pcx_end(d, pos):
    """Decode the PCX run-length data until the full image is accounted for."""
    n = len(d)
    if pos + 128 > n:
        return None
    h = bytes(d[pos:pos + 128])
    if h[0] != 0x0A or h[1] not in (0, 2, 3, 4, 5) or h[2] != 1 or h[3] not in (1, 2, 4, 8) or h[64] != 0:
        return None
    xmin, ymin, xmax, ymax = struct.unpack_from("<4H", h, 4)
    planes, bpl = h[65], struct.unpack_from("<H", h, 66)[0]
    if xmax < xmin or ymax < ymin or planes not in (1, 3, 4) or bpl == 0:
        return None
    need = bpl * planes * (ymax - ymin + 1)
    if need > MAX_SIZE:
        return None
    i, got, lim = pos + 128, 0, min(n, pos + MAX_SIZE)
    while got < need and i < lim:
        b = d[i]
        i += 1
        if b & 0xC0 == 0xC0:
            got += b & 0x3F
            i += 1
        else:
            got += 1
    if got < need:
        return None
    if h[1] == 5 and h[3] == 8 and planes == 1 and i < n and d[i] == 0x0C:
        i += 769  # trailing 256-colour palette
    return i if i <= n else None


FORMATS = [  # (extension, header bytes, end-finder)
    ("jpg", b"\xff\xd8\xff", jpg_end),
    ("png", b"\x89PNG\r\n\x1a\n", png_end),
    ("gif", b"GIF8", gif_end),
    ("bmp", b"BM", bmp_end),
    ("tif", b"II*\x00", tif_end),
    ("tif", b"MM\x00*", tif_end),
    ("pcx", b"\x0a", pcx_end),
]


def is_valid(blob):
    """True if Pillow fully decodes the file, False if not, None if Pillow is missing."""
    try:
        from PIL import Image
    except ImportError:
        return None
    try:
        Image.open(io.BytesIO(blob)).load()
        return True
    except Exception:
        return False


def carve(image_path, out_dir="output/recovered", skip_ranges=None):
    """Carve files from the image. skip_ranges: (start, end) byte ranges held by files
    that still exist; they are skipped so only unallocated space is carved."""
    os.makedirs(out_dir, exist_ok=True)
    log = []
    skips = sorted(skip_ranges or [])
    si = 0
    with open(image_path, "rb") as f, \
         mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as d:
        n, pos = len(d), 0
        while pos + 16 <= n:
            while si < len(skips) and skips[si][1] <= pos:
                si += 1
            if si < len(skips) and skips[si][0] <= pos:
                pos = -(-skips[si][1] // ALIGN) * ALIGN  # jump past a live file
                continue
            hit = None
            for ext, head, finder in FORMATS:
                if d[pos:pos + len(head)] == head:
                    try:
                        end = finder(d, pos)
                    except (struct.error, IndexError):
                        end = None
                    if end and end > pos:
                        hit = (ext, end)
                        break
            if hit is None:
                pos += ALIGN
                continue
            ext, end = hit
            blob = bytes(d[pos:end])
            name = f"{ext}_{pos:010d}.{ext}"
            with open(os.path.join(out_dir, name), "wb") as out:
                out.write(blob)
            log.append({
                "method": "carving",
                "file": name, "type": ext, "offset": pos, "sector": pos // ALIGN,
                "size": len(blob), "valid": is_valid(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "md5": hashlib.md5(blob).hexdigest(),
            })
            pos = -(-end // ALIGN) * ALIGN  # resume at the next sector after this file
    with open(os.path.join(out_dir, "carve_log.json"), "w") as f:
        json.dump(log, f, indent=2)
    return log


if __name__ == "__main__":
    result = carve(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "output/recovered")
    print(f"Carved {len(result)} candidates, {sum(1 for r in result if r['valid'])} valid")
    for r in result:
        print(f"sector {r['sector']:>8}  {r['type']}  {r['size']:>9} bytes  valid={r['valid']}  {r['file']}")