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

KNOWN_HASHES = {
    "BA93C413EC213445DA25C70700DB0D195DF3A2EB60E1601905BA2B9DC1A1FB26".casefold(): "WMMT5DX+ Japanese Update 5 Dump (2017)"
}

BAD_HASHES = {
    "738E88B4D03EF6AB84208464D470E69557A8591CF5A293570BADB1DFDCBC3B2A".casefold(): "WMMT5DX+ English Patched Dump (2016)",
    "92F02199A44FA65A35AF3ED162B5CE5477CFC8B2E3A13CCC95936356680F1479".casefold(): "WMMT6 Japanese Dump (2018)",
    "798EC25B33669071331FA6DFC05A8C385B87F01026F3C32290D07890F58C45A1".casefold(): "WMMT5 Japanese Dump (2018)"
}

IMAGE_BASE = 0x140000000

# Base Resolution Offsets (Virtual Addresses)
RES_PATCHES = [
    (0x140b8426e + 4, 'width'),
    (0x140b8427b + 4, 'height'),
    (0x140236129 + 2, 'width'),
    (0x14023612f + 2, 'height'),
    (0x140b849a7 + 4, 'width'),
    (0x140b849af + 4, 'height'),
]

# Aspect Ratio Float Offset (validation guard only -- never written for 16:9)
# Instruction: C7 43 0C [AB AA E2 3F] -> Float starts 3 bytes in.
# This is the main camera ctor's aspect literal, 1360/768 = the aspect of the
# game's *virtual* coordinate space. A resolution change alters pixel density,
# not that space, so 16:9 targets leave it alone -- which is what the 2016
# reference patcher does. Only ultrawide needs it rewritten, to the aspect of
# the widened virtual space (2.3703704 for 2560x1080).
ASPECT_RATIO_VA = 0x1400ea566 + 3
ASPECT_RATIO_ORIGINAL = b'\xAB\xAA\xE2\x3F'

# UI Scale Trampoline Offsets
# These are the two `movss <matrix m10>, <reg holding 1.0>` sites that the 2016
# reference patcher hooks. The 2017 build has THREE copies of this matrix setup;
# hook 2 must be the branch-target copy (xmm0), not the fall-through copy (xmm14).
HOOK_1_VA = 0x1409426b8  # movss [rbp-0x58], xmm11   (6 bytes)
HOOK_2_VA = 0x1409449b9  # movss [rbp-0x28], xmm0    (5 bytes)

# Code Cave splits (carving up the space between 140ee4f7c - 140ee4fff)
CAVE_1_VA = 0x140ee4f80
CAVE_2_VA = 0x140ee4fa0  

# Expected original bytes (for safety checks)
HOOK_1_ORIGINAL = b'\xF3\x44\x0F\x11\x5D\xA8'
HOOK_2_ORIGINAL = b'\xF3\x0F\x11\x45\xD8'


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

def generate_trampoline(cave_va, hook_va, float_multiplier, reg_type):
    """Rebuild the hooked store as: slot = mult; reg *= slot; slot = reg.

    The multiply is deliberate: in both hooked functions the register holds a
    function-wide 1.0 that is reused for the matrix m15 term (and, for XMM11,
    for a dozen later `unpcklps xmm1, xmm11` position vectors). The 2016
    reference patch scales that constant too -- that is the mechanism, not a
    side effect -- so we reproduce it exactly.
    """
    float_bytes = struct.pack('<f', float_multiplier)

    if reg_type == "XMM11":
        # movss [rbp-0x58], xmm11 -> 6 bytes replaced (REX-prefixed encodings)
        body = (b'\xC7\x45\xA8' + float_bytes
                + b'\xF3\x44\x0F\x59\x5D\xA8'
                + b'\xF3\x44\x0F\x11\x5D\xA8')
        hook_len = 6
    elif reg_type == "XMM0":
        # movss [rbp-0x28], xmm0 -> 5 bytes replaced (no REX)
        body = (b'\xC7\x45\xD8' + float_bytes
                + b'\xF3\x0F\x59\x45\xD8'
                + b'\xF3\x0F\x11\x45\xD8')
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
    print("This patcher only supports the WMMT5DX+ Japanese Update 5 Dump (2017) executable.")
    exe_name = input("Enter the executable filename (e.g., wmn5r.exe): ").strip()
    if not os.path.exists(exe_name):
        log("File not found!", "ERROR")
        return

    current_hash = calculate_sha256(exe_name)
    if current_hash.casefold() in KNOWN_HASHES:
        version_name = KNOWN_HASHES[current_hash]
        log(f"Executable recognized: {version_name}", "SUCCESS")
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

    ui_scale_mult = 765.0 / target_h   # matches the 2016 reference patcher
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
    # See ASPECT_RATIO_VA above -- the reference patcher only rewrites this for
    # ultrawide. Changing it for 16:9 desyncs the 3D view from the 2D UI layer,
    # which stays in the 1360x768 virtual space.
    log(f"Camera aspect left at native 1.770833 at VA {hex(ASPECT_RATIO_VA)}", "INFO")
    print(f"    Unchanged: {format_bytes(file_data[aspect_offset:aspect_offset+4])}\n")

    # 3. Generate and write trampolines to Code Caves
    cave1_payload = generate_trampoline(CAVE_1_VA, HOOK_1_VA, ui_scale_mult, "XMM11")
    cave2_payload = generate_trampoline(CAVE_2_VA, HOOK_2_VA, ui_scale_mult, "XMM0")

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

    # Save Patched File
    output_name = exe_name.replace(".exe", f"_{target_w}x{target_h}.exe")
    with open(output_name, 'wb') as f:
        f.write(file_data)
    
    print("-" * 55)
    log(f"Patch applied successfully! Saved as {output_name}", "SUCCESS")

if __name__ == "__main__":
    main()