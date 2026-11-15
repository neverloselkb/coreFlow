use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn smoothstep(edge0: f32, edge1: f32, x: f32) -> f32 {
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn lerp(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
}

fn mix_color(c1: [f32; 3], c2: [f32; 3], t: f32) -> [f32; 3] {
    let t = t.clamp(0.0, 1.0);
    [
        lerp(c1[0], c2[0], t),
        lerp(c1[1], c2[1], t),
        lerp(c1[2], c2[2], t),
    ]
}

fn dist_to_segment(px: f32, py: f32, ax: f32, ay: f32, bx: f32, by: f32) -> f32 {
    let vx = bx - ax;
    let vy = by - ay;
    let wx = px - ax;
    let wy = py - ay;
    let c1 = vx * wx + vy * wy;
    if c1 <= 0.0 {
        return ((px - ax).powi(2) + (py - ay).powi(2)).sqrt();
    }
    let c2 = vx * vx + vy * vy;
    if c2 <= c1 {
        return ((px - bx).powi(2) + (py - by).powi(2)).sqrt();
    }
    let b = c1 / c2;
    let pbx = ax + b * vx;
    let pby = ay + b * vy;
    ((px - pbx).powi(2) + (py - pby).powi(2)).sqrt()
}

fn sd_rounded_box(px: f32, py: f32, bx: f32, by: f32, r: f32) -> f32 {
    let qx = px.abs() - bx + r;
    let qy = py.abs() - by + r;
    let out_dist = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
    let in_dist = qx.max(qy).min(0.0);
    out_dist + in_dist - r
}

/// Renders the CoreFlow icon at `size x size` in RGBA8888 (top-to-bottom).
fn render_coreflow_icon(size: u32) -> Vec<u8> {
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    let n = size as f32;
    let aa = 2.0 / n;

    let wave_pts: &[(f32, f32)] = &[
        (-0.56, 0.08),
        (-0.30, 0.08),
        (-0.16, -0.44),
        (0.05, 0.44),
        (0.22, -0.22),
        (0.36, 0.08),
        (0.56, 0.08),
    ];

    for y in 0..size {
        for x in 0..size {
            let u = ((x as f32 + 0.5) / n) * 2.0 - 1.0;
            let v = 1.0 - ((y as f32 + 0.5) / n) * 2.0;

            let d_badge = sd_rounded_box(u, v, 0.88, 0.88, 0.40);
            let badge_alpha = 1.0 - smoothstep(-aa, aa, d_badge);
            if badge_alpha <= 0.001 {
                continue;
            }

            let bg_t = ((u * 0.5 - v * 0.7) + 1.0) * 0.5;
            let mut col = mix_color([13.0, 18.0, 30.0], [24.0, 32.0, 52.0], bg_t);

            let r_center = (u * u + v * v).sqrt();
            let core_glow = (-r_center * r_center * 3.2).exp();
            col = mix_color(col, [0.0, 185.0, 255.0], core_glow * 0.25);

            let border_dist = (d_badge + 0.045).abs();
            let border_mask = 1.0 - smoothstep(0.0, 0.045 + aa, border_dist);
            let grad_angle = (u + v + 2.0) * 0.25;
            let rim_col = mix_color([0.0, 235.0, 255.0], [110.0, 95.0, 255.0], grad_angle);
            col = mix_color(col, rim_col, border_mask * 0.88);

            let d_chip = sd_rounded_box(u, v, 0.54, 0.54, 0.16);
            let chip_ring = 1.0 - smoothstep(0.0, 0.028 + aa, d_chip.abs());
            col = mix_color(col, [56.0, 130.0, 210.0], chip_ring * 0.42);

            for &offset in &[-0.26f32, 0.0, 0.26] {
                let d_pin_tb = (u - offset).abs().max(v.abs() - 0.64).max(0.56 - v.abs());
                let d_pin_lr = (v - offset).abs().max(u.abs() - 0.64).max(0.56 - u.abs());
                let d_pin = d_pin_tb.min(d_pin_lr);
                let pin_mask = 1.0 - smoothstep(0.022, 0.022 + aa, d_pin);
                col = mix_color(col, [0.0, 210.0, 255.0], pin_mask * 0.50);
            }

            let mut min_wave_dist = 10.0f32;
            for seg in wave_pts.windows(2) {
                let (ax, ay) = seg[0];
                let (bx, by) = seg[1];
                let d = dist_to_segment(u, v, ax, ay, bx, by);
                if d < min_wave_dist {
                    min_wave_dist = d;
                }
            }

            let wave_x_t = ((u + 0.56) / 1.12).clamp(0.0, 1.0);
            let wave_tint = if wave_x_t < 0.5 {
                mix_color([0.0, 245.0, 160.0], [0.0, 225.0, 255.0], wave_x_t * 2.0)
            } else {
                mix_color(
                    [0.0, 225.0, 255.0],
                    [95.0, 135.0, 255.0],
                    (wave_x_t - 0.5) * 2.0,
                )
            };

            let wave_bloom = (-min_wave_dist * 11.5).exp();
            col = mix_color(col, wave_tint, (wave_bloom * 0.55).clamp(0.0, 1.0));

            let thickness = if size <= 20 {
                0.105
            } else if size <= 32 {
                0.088
            } else {
                0.074
            };
            let stroke_mask = 1.0 - smoothstep(thickness - aa, thickness + aa, min_wave_dist);
            col = mix_color(col, wave_tint, stroke_mask);

            let core_line_mask =
                1.0 - smoothstep(thickness * 0.38 - aa, thickness * 0.38 + aa, min_wave_dist);
            col = mix_color(col, [240.0, 252.0, 255.0], core_line_mask * 0.82);

            let d_end1 = ((u + 0.56).powi(2) + (v - 0.08).powi(2)).sqrt();
            let d_end2 = ((u - 0.56).powi(2) + (v - 0.08).powi(2)).sqrt();
            let dot_r = thickness * 1.35;
            let dot_mask = 1.0 - smoothstep(dot_r - aa, dot_r + aa, d_end1.min(d_end2));
            col = mix_color(col, [255.0, 255.0, 255.0], dot_mask * 0.9);

            let idx = ((y * size + x) * 4) as usize;
            rgba[idx] = col[0].round().clamp(0.0, 255.0) as u8;
            rgba[idx + 1] = col[1].round().clamp(0.0, 255.0) as u8;
            rgba[idx + 2] = col[2].round().clamp(0.0, 255.0) as u8;
            rgba[idx + 3] = (badge_alpha * 255.0).round().clamp(0.0, 255.0) as u8;
        }
    }
    rgba
}

fn rgba_to_icon_dib(size: u32, rgba: &[u8]) -> Vec<u8> {
    let xor_bytes = (size * size * 4) as usize;
    let mask_row_bytes = (((size + 31) / 32) * 4) as usize;
    let and_bytes = mask_row_bytes * (size as usize);
    let mut dib = Vec::with_capacity(40 + xor_bytes + and_bytes);

    dib.extend_from_slice(&40u32.to_le_bytes());
    dib.extend_from_slice(&(size as i32).to_le_bytes());
    dib.extend_from_slice(&((size * 2) as i32).to_le_bytes());
    dib.extend_from_slice(&1u16.to_le_bytes());
    dib.extend_from_slice(&32u16.to_le_bytes());
    dib.extend_from_slice(&0u32.to_le_bytes());
    dib.extend_from_slice(&(xor_bytes as u32).to_le_bytes());
    dib.extend_from_slice(&0i32.to_le_bytes());
    dib.extend_from_slice(&0i32.to_le_bytes());
    dib.extend_from_slice(&0u32.to_le_bytes());
    dib.extend_from_slice(&0u32.to_le_bytes());

    for y in (0..size).rev() {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            dib.push(rgba[idx + 2]);
            dib.push(rgba[idx + 1]);
            dib.push(rgba[idx]);
            dib.push(rgba[idx + 3]);
        }
    }

    for y in (0..size).rev() {
        let mut row = vec![0u8; mask_row_bytes];
        for x in 0..size {
            let a = rgba[((y * size + x) * 4 + 3) as usize];
            if a < 8 {
                let byte_idx = (x / 8) as usize;
                let bit_idx = 7 - (x % 8);
                row[byte_idx] |= 1 << bit_idx;
            }
        }
        dib.extend_from_slice(&row);
    }

    dib
}

fn build_ico_file(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let count = entries.len() as u16;
    let mut ico = Vec::new();
    ico.extend_from_slice(&0u16.to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&count.to_le_bytes());

    let mut offset = 6u32 + (entries.len() as u32) * 16;
    for (size, dib) in entries {
        let dim_byte = if *size >= 256 { 0u8 } else { *size as u8 };
        ico.push(dim_byte);
        ico.push(dim_byte);
        ico.push(0);
        ico.push(0);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(dib.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += dib.len() as u32;
    }

    for (_, dib) in entries {
        ico.extend_from_slice(dib);
    }
    ico
}

fn write_dir_header(out: &mut Vec<u8>, num_id_entries: u16) {
    out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    out.extend_from_slice(&0u16.to_le_bytes()); // MajorVersion
    out.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    out.extend_from_slice(&0u16.to_le_bytes()); // NumberOfNamedEntries
    out.extend_from_slice(&num_id_entries.to_le_bytes()); // NumberOfIdEntries
}

fn write_dir_entry(out: &mut Vec<u8>, id: u32, offset: u32, is_subdir: bool) {
    out.extend_from_slice(&id.to_le_bytes());
    let off = if is_subdir {
        0x8000_0000 | offset
    } else {
        offset
    };
    out.extend_from_slice(&off.to_le_bytes());
}

/// Builds a 64-bit Windows COFF object file (`.o`) containing a `.rsrc` resource section
/// with `RT_ICON` (3) and `RT_GROUP_ICON` (14) so MinGW `ld` / `x86_64-w64-mingw32-gcc` links
/// the application icon directly into `CoreFlow.exe`.
fn build_coff_rsrc_object(entries: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let n_icons = entries.len();
    let total_res = n_icons + 1; // N icons + 1 group icon

    // Build GRPICONDIR payload for RT_GROUP_ICON (id = 1)
    let mut grp = Vec::new();
    grp.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    grp.extend_from_slice(&1u16.to_le_bytes()); // idType = 1
    grp.extend_from_slice(&(n_icons as u16).to_le_bytes()); // idCount
    for (idx, (size, dib)) in entries.iter().enumerate() {
        let dim_byte = if *size >= 256 { 0u8 } else { *size as u8 };
        let icon_id = (idx + 1) as u16;
        grp.push(dim_byte);
        grp.push(dim_byte);
        grp.push(0);
        grp.push(0);
        grp.extend_from_slice(&1u16.to_le_bytes());
        grp.extend_from_slice(&32u16.to_le_bytes());
        grp.extend_from_slice(&(dib.len() as u32).to_le_bytes());
        grp.extend_from_slice(&icon_id.to_le_bytes());
    }

    // Calculate offsets inside `.rsrc` section:
    // Level 1: Root dir = 16 + 2 * 8 = 32 bytes (offset 0..32)
    let off_dir_type3 = 32u32;
    let size_dir_type3 = 16 + (n_icons as u32) * 8;
    let off_dir_type14 = off_dir_type3 + size_dir_type3;
    let size_dir_type14 = 16 + 8;

    // Level 3: Language dirs (`total_res` directories, each 16 + 8 = 24 bytes)
    let off_lang_base = off_dir_type14 + size_dir_type14;
    let off_data_entries_base = off_lang_base + (total_res as u32) * 24;
    let off_payloads_base = off_data_entries_base + (total_res as u32) * 16;

    let mut rsrc = Vec::new();

    // 1. Level 1 Root Directory
    write_dir_header(&mut rsrc, 2);
    write_dir_entry(&mut rsrc, 3, off_dir_type3, true); // RT_ICON = 3
    write_dir_entry(&mut rsrc, 14, off_dir_type14, true); // RT_GROUP_ICON = 14

    // 2. Level 2 Type 3 (RT_ICON) Directory
    write_dir_header(&mut rsrc, n_icons as u16);
    for i in 0..n_icons {
        let lang_off = off_lang_base + (i as u32) * 24;
        write_dir_entry(&mut rsrc, (i + 1) as u32, lang_off, true);
    }

    // 3. Level 2 Type 14 (RT_GROUP_ICON) Directory
    write_dir_header(&mut rsrc, 1);
    let grp_lang_off = off_lang_base + (n_icons as u32) * 24;
    write_dir_entry(&mut rsrc, 1, grp_lang_off, true);

    // 4. Level 3 Language Directories
    for k in 0..total_res {
        write_dir_header(&mut rsrc, 1);
        let data_entry_off = off_data_entries_base + (k as u32) * 16;
        write_dir_entry(&mut rsrc, 0x0409, data_entry_off, false);
    }

    // 5. Compute payload offsets & write IMAGE_RESOURCE_DATA_ENTRY records
    let mut payloads_blob = Vec::new();
    let mut reloc_virtual_addrs = Vec::with_capacity(total_res);

    for (k, payload) in entries
        .iter()
        .map(|(_, d)| d.as_slice())
        .chain(std::iter::once(grp.as_slice()))
        .enumerate()
    {
        let payload_off = off_payloads_base + (payloads_blob.len() as u32);
        let entry_off = off_data_entries_base + (k as u32) * 16;
        reloc_virtual_addrs.push(entry_off);

        rsrc.extend_from_slice(&payload_off.to_le_bytes()); // OffsetToData (relocated by ADDR32NB)
        rsrc.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // Size
        rsrc.extend_from_slice(&0u32.to_le_bytes()); // CodePage
        rsrc.extend_from_slice(&0u32.to_le_bytes()); // Reserved

        payloads_blob.extend_from_slice(payload);
        while payloads_blob.len() % 8 != 0 {
            payloads_blob.push(0);
        }
    }

    rsrc.extend_from_slice(&payloads_blob);

    // Build 64-bit COFF Object File
    let num_relocs = reloc_virtual_addrs.len() as u16;
    let header_and_sec_size = 20u32 + 40u32; // IMAGE_FILE_HEADER (20) + 1 IMAGE_SECTION_HEADER (40)
    let ptr_to_raw_data = header_and_sec_size;
    let ptr_to_relocs = ptr_to_raw_data + (rsrc.len() as u32);
    let ptr_to_symtab = ptr_to_relocs + (num_relocs as u32) * 10;

    let mut coff = Vec::new();
    // IMAGE_FILE_HEADER (20 bytes)
    coff.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine = IMAGE_FILE_MACHINE_AMD64
    coff.extend_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
    coff.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    coff.extend_from_slice(&ptr_to_symtab.to_le_bytes()); // PointerToSymbolTable
    coff.extend_from_slice(&1u32.to_le_bytes()); // NumberOfSymbols = 1 (.rsrc)
    coff.extend_from_slice(&0u16.to_le_bytes()); // SizeOfOptionalHeader = 0
    coff.extend_from_slice(&0u16.to_le_bytes()); // Characteristics = 0

    // IMAGE_SECTION_HEADER (40 bytes)
    coff.extend_from_slice(b".rsrc\0\0\0"); // Name (8 bytes)
    coff.extend_from_slice(&0u32.to_le_bytes()); // VirtualSize
    coff.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
    coff.extend_from_slice(&(rsrc.len() as u32).to_le_bytes()); // SizeOfRawData
    coff.extend_from_slice(&ptr_to_raw_data.to_le_bytes()); // PointerToRawData
    coff.extend_from_slice(&ptr_to_relocs.to_le_bytes()); // PointerToRelocations
    coff.extend_from_slice(&0u32.to_le_bytes()); // PointerToLinenumbers
    coff.extend_from_slice(&num_relocs.to_le_bytes()); // NumberOfRelocations
    coff.extend_from_slice(&0u16.to_le_bytes()); // NumberOfLinenumbers
    // Characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA (0x40) | IMAGE_SCN_MEM_READ (0x40000000)
    coff.extend_from_slice(&0x4000_0040u32.to_le_bytes());

    // Section Raw Data (.rsrc)
    coff.extend_from_slice(&rsrc);

    // Relocations (each 10 bytes: VirtualAddress(4), SymbolTableIndex(4), Type(2))
    for rva_off in reloc_virtual_addrs {
        coff.extend_from_slice(&rva_off.to_le_bytes());
        coff.extend_from_slice(&0u32.to_le_bytes()); // Symbol 0 (.rsrc)
        coff.extend_from_slice(&0x0003u16.to_le_bytes()); // IMAGE_REL_AMD64_ADDR32NB
    }

    // Symbol Table: 1 entry (18 bytes) for `.rsrc` section base
    coff.extend_from_slice(b".rsrc\0\0\0"); // ShortName
    coff.extend_from_slice(&0u32.to_le_bytes()); // Value = 0
    coff.extend_from_slice(&1i16.to_le_bytes()); // SectionNumber = 1
    coff.extend_from_slice(&0u16.to_le_bytes()); // Type = 0
    coff.push(3u8); // StorageClass = IMAGE_SYM_CLASS_STATIC (3)
    coff.push(0u8); // NumberOfAuxSymbols = 0

    // String Table (4 bytes, empty)
    coff.extend_from_slice(&4u32.to_le_bytes());

    coff
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let sizes = [256u32, 64, 48, 32, 16];
    let mut entries = Vec::with_capacity(sizes.len());
    for &sz in &sizes {
        let rgba = render_coreflow_icon(sz);
        let dib = rgba_to_icon_dib(sz, &rgba);
        entries.push((sz, dib));
    }

    let ico_bytes = build_ico_file(&entries);
    let coff_bytes = build_coff_rsrc_object(&entries);

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let assets_dir = manifest_dir.join("assets");
    let _ = fs::create_dir_all(&assets_dir);
    let ico_path = assets_dir.join("coreflow.ico");
    if let Ok(mut f) = File::create(&ico_path) {
        let _ = f.write_all(&ico_bytes);
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_ico_path = out_dir.join("coreflow.ico");
    if let Ok(mut f) = File::create(&out_ico_path) {
        let _ = f.write_all(&ico_bytes);
    }

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        let obj_path = out_dir.join("coreflow_icon.o");
        if let Ok(mut f) = File::create(&obj_path) {
            let _ = f.write_all(&coff_bytes);
        }
        println!("cargo:rustc-link-arg-bins={}", obj_path.display());
    }
}
