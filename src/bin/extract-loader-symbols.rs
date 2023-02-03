/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use byteorder::{ByteOrder, LittleEndian};
use std::env;
use std::fs::File;
use std::io::Write;

const LOADER_SYM_PTR: usize = 0x1c564;

fn read_string(data: &[u8]) -> String {
    let len = data[0] as usize;
    let s = &data[1..len + 1];
    return if let Ok(s) = std::str::from_utf8(&s) {
        s.to_string()
    } else {
        "?".to_string()
    }
}

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("usage: {} memory.bin out.txt", args[0]);
        return Ok(())
    }

    let memory_fname = &args[1];
    let out_fname = &args[2];

    let memory_data = std::fs::read(memory_fname)?;

    // Look up the pointer
    let mut sym_ptr = LittleEndian::read_u32(&memory_data[LOADER_SYM_PTR..LOADER_SYM_PTR + 4]) as usize;

    let mut f = File::create(out_fname)?;
    while sym_ptr != 0 {
        let next_ptr = LittleEndian::read_u32(&memory_data[sym_ptr+0..sym_ptr+4]) as usize;
        let func_ptr = LittleEndian::read_u32(&memory_data[sym_ptr+4..sym_ptr+8]) as usize;
        let name_ptr = LittleEndian::read_u32(&memory_data[sym_ptr+8..sym_ptr+12]) as usize;

        let name = read_string(&memory_data[name_ptr..]);
        writeln!(f, "{} 0x{:x}", name, func_ptr)?;
        sym_ptr = next_ptr;
    }

    Ok(())
}
