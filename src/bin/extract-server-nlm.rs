/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use byteorder::{ByteOrder, LittleEndian};
use std::env;

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("usage: {} file.nlm server.exe out.nlm", args[0]);
        return Ok(())
    }

    let server_fname = &args[1];
    let nlm_fname = &args[2];

    let server_data = std::fs::read(server_fname)?;

    // Locate HERE signature
    let mut here_offset: Option<usize> = None;
    for n in 0..0x1000 {
        let piece = &server_data[n..n+4];
        if piece == b"HERE" {
            here_offset = Some(n);
            break;
        }
    }
    if here_offset.is_none() {
        println!("HERE signature not found");
        return Ok(())
    }
    let here_offset = here_offset.unwrap() as usize;

    let x = LittleEndian::read_u16(&server_data[here_offset + 0x2a..here_offset + 0x2c]);
    let y = LittleEndian::read_u16(&server_data[here_offset + 0x2c..here_offset + 0x2e]);
    if x != 0 || y != 0x110 {
        println!("WARNING: unexpected version (?) words read, got {:x} {:x}", x, y);
    }

    let nlm_offset = LittleEndian::read_u32(&server_data[here_offset + 0x18..here_offset + 0x1c]) as usize;

    let nlm_magic = [
        'N' as u8, 'e' as u8, 't' as u8, 'W' as u8, 'a' as u8, 'r' as u8,
        'e' as u8, ' ' as u8, 'L' as u8, 'o' as u8, 'a' as u8, 'd' as u8,
        'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, ' ' as u8, 'M' as u8,
        'o' as u8, 'd' as u8, 'u' as u8, 'l' as u8, 'e' as u8, 0x1a as u8 ];
    if &server_data[nlm_offset..nlm_offset + nlm_magic.len()] != nlm_magic {
        println!("Signature found, but NLM at that offset has invalid magic");
        return Ok(());
    }

    std::fs::write(nlm_fname, &server_data[nlm_offset..])?;
    Ok(())
}
