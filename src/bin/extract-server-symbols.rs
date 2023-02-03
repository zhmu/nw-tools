/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use byteorder::{ByteOrder, LittleEndian};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use object::{Object, ObjectSection};

const SERVER_SYM_PTR: usize = 0x40021628;

fn read_string(data: &[u8]) -> String {
    let len = data[0] as usize;
    let s = &data[1..len + 1];
    return if let Ok(s) = std::str::from_utf8(&s) {
        s.to_string()
    } else {
        "?".to_string()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("usage: {} server.elf out.txt", args[0]);
        return Ok(())
    }

    let server_fname = &args[1];
    let out_fname = &args[2];

    let server_data = std::fs::read(server_fname)?;

    let elf = object::File::parse(&*server_data)?;
    let mut base: usize = 0;
    let mut data: Option<Vec<u8>> = None;
    for s in elf.sections() {
        if s.kind() != object::SectionKind::Data { continue; }
        if let Ok(c) = s.uncompressed_data() {
            if data.is_some() {
                println!("multiple data sections found");
                return Ok(())
            }
            base = s.address() as usize;
            data = Some(c.to_vec());
            break;
        }
    }
    if data.is_none() {
        println!("unable to find data section");
        return Ok(())
    }
    let data = data.unwrap();
    println!("{:x}", base);

    // Look up the pointer
    let sym_addr = SERVER_SYM_PTR - base;
    let mut sym_ptr = LittleEndian::read_u32(&data[sym_addr..sym_addr + 4]) as usize;

    let mut f = File::create(out_fname)?;
    while sym_ptr != 0 {
        let sym_addr = sym_ptr - base;
        let next_ptr = LittleEndian::read_u32(&data[sym_addr+0..sym_addr+4]) as usize;
        let func_ptr = LittleEndian::read_u32(&data[sym_addr+4..sym_addr+8]) as usize;
        let name_ptr = LittleEndian::read_u32(&data[sym_addr+8..sym_addr+12]) as usize;

        let name = read_string(&data[name_ptr - base..]);
        writeln!(f, "{} 0x{:x}", name, func_ptr)?;
        sym_ptr = next_ptr;
    }

    Ok(())
}
