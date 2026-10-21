"""Compare carved files with NIST's published L0_Graphic layout and the original files.

Usage: python verify.py output/recovered/carve_log.json path/to/original_files
"""
import hashlib, json, os, sys

# Published layout for L0_Graphic.dd (NIST CFReDS "Image Layouts"): name -> (start sector, size in bytes)
LAYOUT = {
    "000_0021.png": (10000, 12966639),
    "02010025.pcx": (45326, 806664),
    "09260002.jpg": (56902, 60716),
    "100_0304crop.bmp": (67021, 5111906),
    "100_0018.tif": (87006, 14969328),
    "100_0183.gif": (126243, 132948),
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_original(folder, name):
    for f in os.listdir(folder):
        if f.lower() == name.lower():
            return os.path.join(folder, f)
    return None


def verify(log_path, originals_dir):
    with open(log_path) as f:
        carved = {r["sector"]: r for r in json.load(f)}
    rows, passed = [], 0
    for name, (sector, size) in LAYOUT.items():
        r = carved.get(sector)
        original = find_original(originals_dir, name)
        row = {"file": name, "sector": sector, "published_size": size,
               "found": r is not None,
               "size_match": bool(r) and r["size"] == size,
               "original_found": original is not None, "hash_match": None}
        if r and original:
            row["hash_match"] = sha256_file(original) == r["sha256"]
        row["pass"] = bool(row["size_match"] and row["hash_match"])
        passed += row["pass"]
        rows.append(row)
    return rows, passed


if __name__ == "__main__":
    rows, passed = verify(sys.argv[1], sys.argv[2])
    print(f"{'file':<18}{'sector':>8}  found  size  hash   result")
    for r in rows:
        print(f"{r['file']:<18}{r['sector']:>8}  {str(r['found']):<5}  "
              f"{str(r['size_match']):<5} {str(r['hash_match']):<6} {'PASS' if r['pass'] else 'FAIL'}")
    print(f"\nRecovered and verified: {passed}/{len(rows)}")
    with open("verification_report.json", "w") as f:
        json.dump({"verified": passed, "total": len(rows), "files": rows}, f, indent=2)
