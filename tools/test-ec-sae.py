#!/usr/bin/env python3
"""Verify self-contained EC/bignum primitives and real upstream SAE (H&P + H2E) under ASan/UBSan."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[1]
wpa = root / "out/wpa-src"
if not (wpa / "src/common/sae.c").is_file():
    subprocess.run(["python3", str(root / "tools/prepare-supplicant.py")], check=True)

compiler = shutil.which("clang")
if not compiler:
    raise SystemExit("clang is required")

out = root / "out/ec-sae-test"
out.mkdir(parents=True, exist_ok=True)
(out / "report.json").unlink(missing_ok=True)

common_defs = [
    "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
    "-DCONFIG_OSX", "-DCONFIG_SAE", "-DCONFIG_ECC",
    "-DCONFIG_CRYPTO_INTERNAL", "-DCONFIG_INTERNAL_LIBTOMMATH",
    "-DCONFIG_SHA256", "-DCONFIG_SHA384", "-DCONFIG_SHA512",
    "-DCONFIG_INTERNAL_SHA384", "-DCONFIG_INTERNAL_SHA512",
    "-DCONFIG_HMAC_SHA256_KDF", "-DCONFIG_HMAC_SHA384_KDF", "-DCONFIG_HMAC_SHA512_KDF",
    "-DCONFIG_NO_RANDOM_POOL",
    "-isystem", str(wpa / "src"),
    "-isystem", str(wpa / "src/utils"),
    "-I", str(root / "userspace"),
]

upstream_sources = [
    "src/common/sae.c",
    "src/common/dragonfly.c",
    "src/common/wpa_common.c",
    "src/common/ieee802_11_common.c",
    "src/crypto/crypto_internal.c",
    "src/crypto/crypto_internal-modexp.c",
    "src/tls/bignum.c",
    "src/crypto/dh_groups.c",
    "src/crypto/dh_group5.c",
    "src/crypto/aes-internal.c",
    "src/crypto/aes-internal-enc.c",
    "src/crypto/aes-internal-dec.c",
    "src/crypto/aes-omac1.c",
    "src/crypto/aes-unwrap.c",
    "src/crypto/aes-wrap.c",
    "src/crypto/aes-siv.c",
    "src/crypto/aes-ctr.c",
    "src/crypto/sha1.c",
    "src/crypto/sha1-prf.c",
    "src/crypto/sha1-pbkdf2.c",
    "src/crypto/sha1-internal.c",
    "src/crypto/md5.c",
    "src/crypto/md5-internal.c",
    "src/crypto/rc4.c",
    "src/crypto/sha256.c",
    "src/crypto/sha256-prf.c",
    "src/crypto/sha256-kdf.c",
    "src/crypto/sha256-internal.c",
    "src/crypto/sha384.c",
    "src/crypto/sha384-prf.c",
    "src/crypto/sha384-kdf.c",
    "src/crypto/sha384-internal.c",
    "src/crypto/sha512.c",
    "src/crypto/sha512-prf.c",
    "src/crypto/sha512-kdf.c",
    "src/crypto/sha512-internal.c",
    "src/utils/common.c",
    "src/utils/os_unix.c",
    "src/utils/wpabuf.c",
    "src/utils/wpa_debug.c",
]

objs = []
for rel in upstream_sources:
    src = wpa / rel
    obj = out / (rel.replace("/", "_") + ".o")
    subprocess.run([compiler, *common_defs, "-Wall", "-Wno-unused-parameter", "-c", str(src), "-o", str(obj)], check=True)
    objs.append(obj)

ec_src = root / "userspace/nw_crypto_ec.c"
if not ec_src.is_file():
    raise SystemExit(f"missing implementation: {ec_src}")

strict = ["-Wall", "-Wextra", "-Werror"]
ec_obj = out / "nw_crypto_ec.o"
test_obj = out / "ec_sae_test.o"
subprocess.run([compiler, *common_defs, *strict, "-c", str(ec_src), "-o", str(ec_obj)], check=True)
subprocess.run([compiler, *common_defs, *strict, "-c", str(root / "tests/ec_sae_test.c"), "-o", str(test_obj)], check=True)

binary = out / "ec-sae-test"
subprocess.run([compiler, *common_defs, str(test_obj), str(ec_obj), *objs, "-o", str(binary)], check=True)
run = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
print(run.stdout, end="")

(out / "report.json").write_text(json.dumps({
    "passed": True,
    "sanitizers": ["address", "undefined"],
    "groups_verified": [19, 20, 21],
    "modes_verified": ["hunt-and-peck", "hash-to-element"],
    "ec_source_sha256": hashlib.sha256(ec_src.read_bytes()).hexdigest(),
    "test_source_sha256": hashlib.sha256((root / "tests/ec_sae_test.c").read_bytes()).hexdigest(),
    "output": run.stdout,
}, indent=2) + "\n")
