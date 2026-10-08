import os
import struct
import hashlib
import shutil
import sys

try:
    import pefile
except ImportError:
    print("Error: The 'pefile' library is required.")
    print("Please run: pip install pefile")
    sys.exit(1)

# --- CONFIGURATION ---

HASH_2017_JP = "BA93C413EC213445DA25C70700DB0D195DF3A2EB60E1601905BA2B9DC1A1FB26".casefold()
HASH_2016_EN = "738E88B4D03EF6AB84208464D470E69557A8591CF5A293570BADB1DFDCBC3B2A".casefold()

BAD_HASHES = {
    "92F02199A44FA65A35AF3ED162B5CE5477CFC8B2E3A13CCC95936356680F1479".casefold(): "WMMT6 Japanese Dump (2018)",
    "798EC25B33669071331FA6DFC05A8C385B87F01026F3C32290D07890F58C45A1".casefold(): "WMMT5 Japanese Dump (2018)"
}

IMAGE_BASE = 0x140000000

# Rival Nameplate Fix (identical code in both builds, only the address differs)
# The world-to-screen helper (only called by the rival marker loop) scales the
# projected point by the *real* render size read at runtime, but its caller adds
# a hardcoded 680/384 -- the centre of the 1360x768 virtual UI space. Pin the
# size to 1360x768 so the plate lands in the same space it is drawn in.
def nameplate_patches(va):
    return [
        # (VA, original, patched)
        (va,     b'\x8B\x98\xD8\x00\x00\x00', b'\xBB' + struct.pack('<I', 1360) + b'\x90'),  # mov ebx, [rax+0xd8] -> mov ebx, 1360
        (va + 6, b'\x8B\xB8\xDC\x00\x00\x00', b'\xBF' + struct.pack('<I', 768) + b'\x90'),   # mov edi, [rax+0xdc] -> mov edi, 768
    ]

# Per-version patch locations (Virtual Addresses)
#
# res_patches: start of each 4-byte width/height immediate.
# aspect_va:   main camera ctor's aspect literal, C7 43 0C [AB AA E2 3F] -> float
#              starts 3 bytes in. Validation guard only -- never written for 16:9.
#              It is 1360/768, the aspect of the game's *virtual* coordinate
#              space. A resolution change alters pixel density, not that space,
#              so 16:9 targets leave it alone. Only ultrawide needs it rewritten.
# hook_1/2:    the two `movss <matrix m10>, <reg holding 1.0>` sites to hook.
#              hook_2_slot is the rbp disp8 of hook 2's matrix slot, which
#              differs between builds.
# cave_1/2:    24-byte trampolines in the zero padding at the end of .text.
VERSIONS = {
    HASH_2017_JP: {
        "name": "WMMT5DX+ Japanese Update 5 Dump (2017)",
        "res_patches": [
            (0x140b8426e + 4, 'width'),
            (0x140b8427b + 4, 'height'),
            (0x140236129 + 2, 'width'),
            (0x14023612f + 2, 'height'),
            (0x140b849a7 + 4, 'width'),
            (0x140b849af + 4, 'height'),
        ],
        "aspect_va": 0x1400ea566 + 3,
        # The 2017 build has THREE copies of the matrix setup; hook 2 must be the
        # branch-target copy (xmm0), not the fall-through copy (xmm14).
        "hook_1_va": 0x1409426b8,   # movss [rbp-0x58], xmm11   (6 bytes)
        "hook_2_va": 0x1409449b9,   # movss [rbp-0x28], xmm0    (5 bytes)
        "hook_2_slot": 0xD8,
        # Carving up the space between 140ee4f7c - 140ee4fff
        "cave_1_va": 0x140ee4f80,
        "cave_2_va": 0x140ee4fa0,
        "nameplate_patches": nameplate_patches(0x1400ea1e4),
    },
    HASH_2016_EN: {
        "name": "WMMT5DX+ English Patched Dump (2016)",
        # File offsets for 2016 version, as VAs
        "res_patches": [
            (0x140233f4b, 'width'),
            (0x140233f51, 'height'),
            (0x140b2cceb, 'width'),
            (0x140b2ccf3, 'height'),
            (0x140b2c5e2, 'width'),
            (0x140b2c5ef, 'height'),
        ],
        "aspect_va": 0x1400ea846 + 3,
        "hook_1_va": 0x1408e9608,   # movss [rbp-0x58], xmm11   (6 bytes)
        "hook_2_va": 0x1408eb7fb,   # movss [rbp-0x78], xmm0    (5 bytes)
        "hook_2_slot": 0x88,
        # Same layout: cave 2 directly follows cave 1
        "cave_1_va": 0x140e7b03c,
        "cave_2_va": 0x140e7b054,
        "nameplate_patches": nameplate_patches(0x1400ea4c4),
    },
}

# Expected original bytes (for safety checks)
ASPECT_RATIO_ORIGINAL = b'\xAB\xAA\xE2\x3F'
HOOK_1_ORIGINAL = b'\xF3\x44\x0F\x11\x5D\xA8'


def log(msg, status="INFO"):
    colors = {"INFO": "\033[94m", "SUCCESS": "\033[92m", "WARN": "\033[93m", "ERROR": "\033[91m"}
    reset = "\033[0m"
    print(f"[{colors.get(status, '')}{status}{reset}] {msg}")

def format_bytes(data):
    """Converts a bytearray/bytes object into a readable hex string (e.g., C7 44 24)."""
    return " ".join(f"{b:02X}" for b in data)

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest().lower()

def get_file_offset(pe, va):
    rva = va - IMAGE_BASE
    return pe.get_offset_from_rva(rva)

def generate_trampoline(cave_va, hook_va, float_multiplier, reg_type, slot=None):
    """Rebuild the hooked store as: slot = mult; reg *= slot; slot = reg.

    The multiply is deliberate: in both hooked functions the register holds a
    function-wide 1.0 that is reused for the matrix m15 term (and, for XMM11,
    for a dozen later `unpcklps xmm1, xmm11` position vectors).
    """
    float_bytes = struct.pack('<f', float_multiplier)

    if reg_type == "XMM11":
        # movss [rbp-0x58], xmm11 -> 6 bytes replaced (REX-prefixed encodings)
        body = (b'\xC7\x45\xA8' + float_bytes
                + b'\xF3\x44\x0F\x59\x5D\xA8'
                + b'\xF3\x44\x0F\x11\x5D\xA8')
        hook_len = 6
    elif reg_type == "XMM0":
        # movss [rbp+slot], xmm0 -> 5 bytes replaced (no REX)
        d = bytes([slot])
        body = (b'\xC7\x45' + d + float_bytes
                + b'\xF3\x0F\x59\x45' + d
                + b'\xF3\x0F\x11\x45' + d)
        hook_len = 5
    else:
        raise ValueError(f"Unknown register type: {reg_type}")

    return_va = hook_va + hook_len
    rel32_back = return_va - (cave_va + len(body) + 5)
    return body + b'\xE9' + struct.pack('<i', rel32_back)


def main():
    print("="*55)
    print(" WMMT5DX+ Resolution & UI Patcher")
    print("="*55)
    print("Supported: WMMT5DX+ Japanese Update 5 Dump (2017) and English Patched Dump (2016).")
    exe_name = input("Enter the executable filename (e.g., wmn5r.exe): ").strip()
    if not os.path.exists(exe_name):
        log("File not found!", "ERROR")
        return

    current_hash = calculate_sha256(exe_name)
    if current_hash.casefold() in VERSIONS:
        version = VERSIONS[current_hash.casefold()]
        log(f"Executable recognized: {version['name']}", "SUCCESS")
    elif current_hash.casefold() in BAD_HASHES:
        version_name = BAD_HASHES[current_hash]
        log(f"Executable recognized: {version_name}", "INFO")
        log("This file is NOT supported. Aborting patch.", "ERROR")
        return
    else:
        log(f"SHA256 not in known list:\nCalculated: {current_hash}", "WARN")
        choice = input("This executable may be unsupported or modified. Continue anyway? (y/n): ")
        if choice.lower() != 'y':
            log("Aborting patch.", "INFO")
            return
        print("\nPatch it as which version?")
        print("1) WMMT5DX+ Japanese Update 5 Dump (2017)")
        print("2) WMMT5DX+ English Patched Dump (2016)")
        choice = input("Choice: ").strip()
        if choice == '1':
            version = VERSIONS[HASH_2017_JP]
        elif choice == '2':
            version = VERSIONS[HASH_2016_EN]
        else:
            log("Invalid choice.", "ERROR")
            return

    print("\nSelect Target Resolution:")
    print("1) 1920 x 1080 (1080p)")
    print("2) 2560 x 1440 (1440p)")
    print("3) 3840 x 2160 (4K)")
    print("4) Custom")
    
    choice = input("Choice: ").strip()
    if choice == '1':
        target_w, target_h = 1920, 1080
    elif choice == '2':
        target_w, target_h = 2560, 1440
    elif choice == '3':
        target_w, target_h = 3840, 2160
    elif choice == '4':
        target_w = int(input("Enter Width: "))
        target_h = int(input("Enter Height: "))
    else:
        log("Invalid choice.", "ERROR")
        return

    RES_PATCHES = version["res_patches"]
    ASPECT_RATIO_VA = version["aspect_va"]
    HOOK_1_VA = version["hook_1_va"]
    HOOK_2_VA = version["hook_2_va"]
    HOOK_2_SLOT = version["hook_2_slot"]
    HOOK_2_ORIGINAL = b'\xF3\x0F\x11\x45' + bytes([HOOK_2_SLOT])
    CAVE_1_VA = version["cave_1_va"]
    CAVE_2_VA = version["cave_2_va"]
    NAMEPLATE_PATCHES = version["nameplate_patches"]

    # ---------------------------------------------------------
    # PHASE 1: VALIDATION (DRY RUN)
    # ---------------------------------------------------------
    print("-" * 55)
    log("Evaluating patch viability...")
    
    try:
        pe = pefile.PE(exe_name)
        file_data = bytearray(open(exe_name, 'rb').read())
    except Exception as e:
        log(f"Failed to parse executable structure: {e}", "ERROR")
        return

    try:
        # Check 1: Can we resolve all base resolution offsets?
        res_offsets = []
        for va, dimension in RES_PATCHES:
            offset = get_file_offset(pe, va)
            res_offsets.append((offset, dimension, va))

        # Check 2: Does the Aspect Ratio match original?
        aspect_offset = get_file_offset(pe, ASPECT_RATIO_VA)
        if file_data[aspect_offset:aspect_offset+4] != ASPECT_RATIO_ORIGINAL:
            log(f"Aspect ratio original bytes mismatch at VA {hex(ASPECT_RATIO_VA)}.", "ERROR")
            log("Please use a clean backup. This file might already be patched.", "ERROR")
            return

        # Check 3: Do the UI hooks contain the exact expected original code?
        h1_offset = get_file_offset(pe, HOOK_1_VA)
        h2_offset = get_file_offset(pe, HOOK_2_VA)

        if file_data[h1_offset:h1_offset+len(HOOK_1_ORIGINAL)] != HOOK_1_ORIGINAL:
            log(f"Hook 1 original bytes mismatch at VA {hex(HOOK_1_VA)}.", "ERROR")
            log("If you are trying to change the resolution of an already-patched game, please patch your clean backup instead.", "ERROR")
            return
            
        if file_data[h2_offset:h2_offset+len(HOOK_2_ORIGINAL)] != HOOK_2_ORIGINAL:
            log(f"Hook 2 original bytes mismatch at VA {hex(HOOK_2_VA)}.", "ERROR")
            return

        # Check 3: Are the Code Caves actually empty? (Payload is 24 bytes long)
        c1_offset = get_file_offset(pe, CAVE_1_VA)
        c2_offset = get_file_offset(pe, CAVE_2_VA)
        
        # Verify 24 bytes of 0x00 at both locations
        if any(b != 0 for b in file_data[c1_offset:c1_offset+24]):
            log(f"Code Cave 1 at VA {hex(CAVE_1_VA)} is not empty!", "ERROR")
            log("Another patch or mod may be utilizing this space. Cannot proceed.", "ERROR")
            return
            
        if any(b != 0 for b in file_data[c2_offset:c2_offset+24]):
            log(f"Code Cave 2 at VA {hex(CAVE_2_VA)} is not empty!", "ERROR")
            return

        # Check 5: Do the nameplate projection sites contain the expected original code?
        nameplate_offsets = []
        for va, original, patched in NAMEPLATE_PATCHES:
            offset = get_file_offset(pe, va)
            if file_data[offset:offset+len(original)] != original:
                log(f"Nameplate original bytes mismatch at VA {hex(va)}.", "ERROR")
                return
            nameplate_offsets.append((offset, va, patched))

    except Exception as e:
        log(f"Validation failed due to structural offset error: {e}", "ERROR")
        return

    log("Validation successful. Executable is ready to patch.", "SUCCESS")
    print("-" * 55)

    # ---------------------------------------------------------
    # PHASE 2: EXECUTION
    # ---------------------------------------------------------
    
    # Create backup (Only happens after validation passes)
    backup_name = exe_name + ".bak"
    if not os.path.exists(backup_name):
        shutil.copy2(exe_name, backup_name)
        log(f"Created backup: {backup_name}", "SUCCESS")
    else:
        log(f"Backup already exists: {backup_name}", "INFO")

    ui_scale_mult = 765.0 / target_h
    log(f"Target UI Multiplier calculated: {ui_scale_mult:.6f}")
    print("-" * 55)

    # 1. Apply Base Resolution Patches
    for offset, dimension, va in res_offsets:
        val = target_w if dimension == 'width' else target_h
        val_bytes = struct.pack('<I', val)
        
        old_bytes = file_data[offset:offset+4]
        file_data[offset:offset+4] = val_bytes
        
        log(f"Patched {dimension} to {val} at VA {hex(va)}", "SUCCESS")
        print(f"    Old: {format_bytes(old_bytes)}  ->  New: {format_bytes(val_bytes)}\n")

    # 2. Camera aspect ratio: deliberately left untouched.
    log(f"Camera aspect left at native 1.770833 at VA {hex(ASPECT_RATIO_VA)}", "INFO")
    print(f"    Unchanged: {format_bytes(file_data[aspect_offset:aspect_offset+4])}\n")

    # 3. Generate and write trampolines to Code Caves
    cave1_payload = generate_trampoline(CAVE_1_VA, HOOK_1_VA, ui_scale_mult, "XMM11")
    cave2_payload = generate_trampoline(CAVE_2_VA, HOOK_2_VA, ui_scale_mult, "XMM0", HOOK_2_SLOT)

    # XMM11 Cave
    old_cave1 = file_data[c1_offset:c1_offset+len(cave1_payload)]
    file_data[c1_offset:c1_offset+len(cave1_payload)] = cave1_payload
    log(f"Injected XMM11 Code Cave at VA {hex(CAVE_1_VA)}", "SUCCESS")
    print(f"    Old: {format_bytes(old_cave1)}")
    print(f"    New: {format_bytes(cave1_payload)}\n")

    # XMM14 Cave
    old_cave2 = file_data[c2_offset:c2_offset+len(cave2_payload)]
    file_data[c2_offset:c2_offset+len(cave2_payload)] = cave2_payload
    log(f"Injected XMM0 Code Cave at VA {hex(CAVE_2_VA)}", "SUCCESS")
    print(f"    Old: {format_bytes(old_cave2)}")
    print(f"    New: {format_bytes(cave2_payload)}\n")

    # 4. Overwrite original instructions with Jumps to Caves
    rel32_h1_to_cave = CAVE_1_VA - (HOOK_1_VA + 5)
    h1_jump_payload = b'\xE9' + struct.pack('<i', rel32_h1_to_cave) + b'\x90'
    
    old_h1 = file_data[h1_offset:h1_offset+6]
    file_data[h1_offset:h1_offset+6] = h1_jump_payload
    log(f"Hooked XMM11 UI logic at VA {hex(HOOK_1_VA)}", "SUCCESS")
    print(f"    Old: {format_bytes(old_h1)}  ->  New: {format_bytes(h1_jump_payload)}\n")

    rel32_h2_to_cave = CAVE_2_VA - (HOOK_2_VA + 5)
    h2_jump_payload = b'\xE9' + struct.pack('<i', rel32_h2_to_cave)

    old_h2 = file_data[h2_offset:h2_offset+len(h2_jump_payload)]
    file_data[h2_offset:h2_offset+len(h2_jump_payload)] = h2_jump_payload
    log(f"Hooked XMM0 UI logic at VA {hex(HOOK_2_VA)}", "SUCCESS")
    print(f"    Old: {format_bytes(old_h2)}  ->  New: {format_bytes(h2_jump_payload)}\n")

    # 5. Rival nameplate projection fix
    for offset, va, patched in nameplate_offsets:
        old_bytes = file_data[offset:offset+len(patched)]
        file_data[offset:offset+len(patched)] = patched
        log(f"Patched rival nameplate projection at VA {hex(va)}", "SUCCESS")
        print(f"    Old: {format_bytes(old_bytes)}  ->  New: {format_bytes(patched)}\n")

    # Save Patched File
    output_name = exe_name.replace(".exe", f"_{target_w}x{target_h}.exe")
    with open(output_name, 'wb') as f:
        f.write(file_data)
    
    print("-" * 55)
    log(f"Patch applied successfully! Saved as {output_name}", "SUCCESS")

if __name__ == "__main__":
    main()
    input("Press Enter to continue...")