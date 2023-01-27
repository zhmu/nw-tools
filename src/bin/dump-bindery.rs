/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2023 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use std::env;
use std::io::{Cursor, Read};
use byteorder::{LittleEndian, ReadBytesExt};

#[derive(Debug)]
pub struct Object {
    pub objid: u32,
    pub objtype: u16,
    pub name: String,
    pub security: u8,
    pub property: u32,
    pub unk1: u32,
}

fn read_objects(data: &[ u8 ]) -> Result<Vec<Object>, std::io::Error> {
    let mut rdr = Cursor::new(data);

    let mut result: Vec<Object> = Vec::new();
    loop {
        let objid = rdr.read_u32::<LittleEndian>();
        if objid.is_err() { break; }
        let objid = objid.unwrap();
        let objtype = rdr.read_u16::<LittleEndian>()?;
        let namelen = rdr.read_u8()?;
        let mut nameval = [ 0u8; 48 ];
        rdr.read_exact(&mut nameval)?;
        let security = rdr.read_u8()?;
        let property = rdr.read_u32::<LittleEndian>()?;
        let unk1 = rdr.read_u32::<LittleEndian>()?;

        let name = std::str::from_utf8(&nameval[0..namelen as usize]).unwrap().to_string();

        let object = Object{
            objid,
            objtype,
            name,
            security,
            property,
            unk1
        };
        result.push(object);
    }

    Ok(result)
}

#[derive(Debug)]
pub struct Property {
    pub propid: u32,
    pub name: String,
    pub flags: u8,
    pub security: u8,
    pub owner: u32,
    pub next: u32,
    pub value: u32,
}

fn read_properties(data: &[ u8 ]) -> Result<Vec<Property>, std::io::Error> {
    let mut rdr = Cursor::new(data);

    let mut result: Vec<Property> = Vec::new();
    loop {
        let propid = rdr.read_u32::<LittleEndian>();
        if propid.is_err() { break; }
        let propid = propid.unwrap();
        let namelen = rdr.read_u8()?;
        let mut nameval = [ 0u8; 15 ];
        rdr.read_exact(&mut nameval)?;
        let flags = rdr.read_u8()?;
        let security = rdr.read_u8()?;
        let owner = rdr.read_u32::<LittleEndian>()?;
        let next = rdr.read_u32::<LittleEndian>()?;
        let value = rdr.read_u32::<LittleEndian>()?;
        let name = std::str::from_utf8(&nameval[0..namelen as usize]).unwrap().to_string();

        let property = Property{
            propid,
            name,
            flags,
            security,
            owner,
            next,
            value
        };
        result.push(property);
    }

    Ok(result)
}

#[derive(Debug)]
pub struct Value {
    pub valueid: u32,
    pub owner: u32,
    pub next: u32,
    pub sequence: u16,
    pub data: [ u8; 128 ],
}

fn read_values(data: &[ u8 ]) -> Result<Vec<Value>, std::io::Error> {
    let mut rdr = Cursor::new(data);

    let mut result: Vec<Value> = Vec::new();
    loop {
        let valueid = rdr.read_u32::<LittleEndian>();
        if valueid.is_err() { break; }
        let valueid = valueid.unwrap();
        let owner = rdr.read_u32::<LittleEndian>()?;
        let next = rdr.read_u32::<LittleEndian>()?;
        let sequence = rdr.read_u16::<LittleEndian>()?;

        let mut data = [ 0u8; 128 ];
        rdr.read_exact(&mut data)?;

        let value = Value{
            valueid,
            owner,
            next,
            sequence,
            data
        };
        result.push(value);
    }

    Ok(result)
}

fn dump_data(data: &[u8], offset: usize, prefix: &str) {
    const BYTES_PER_LINE: usize  = 16;
    for index in (0..data.len()).step_by(BYTES_PER_LINE) {
        print!("{}{:08x}  ", prefix, offset + index);
        for n in 0..BYTES_PER_LINE {
            let b = data[index + n];
            print!(" {:02x}", b);
        }
        print!("  |");
        for n in 0..BYTES_PER_LINE {
            let b = data[index + n] as char;
            if b.is_ascii_alphanumeric() {
                print!("{}", b);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("usage: {} net$obj.sys net$prop.sys net$val.sys", args[0]);
        return Ok(())
    }
    let obj_fname = &args[1];
    let prop_fname = &args[2];
    let val_fname = &args[3];

    let obj_data = std::fs::read(obj_fname)?;
    let prop_data = std::fs::read(prop_fname)?;
    let val_data = std::fs::read(val_fname)?;

    let objects = read_objects(&obj_data)?;
    let properties = read_properties(&prop_data)?;
    let values = read_values(&val_data)?;

    for o in objects {
        println!("object id {:x} type {:x} security {:x} name '{}'", o.objid, o.objtype, o.security, o.name);
        let mut propertyid = o.property;
        while propertyid != 0xffffffff {
            let p = properties.iter().filter(|x| x.propid == propertyid).next().expect("property not found");
            println!("  property id {:x} flags {:x} security {:x} owner {:x} name '{}'", p.propid, p.flags, p.security, p.owner, p.name);
            let mut valueid = p.value;
            let mut offset = 0;
            while valueid != 0xffffffff {
                let v = values.iter().filter(|x| x.valueid == valueid).next().expect("value not found");
                println!("    value owner {:x} sequence {:x}", v.owner, v.sequence);
                dump_data(&v.data, offset, "      ");
                offset += v.data.len();
                valueid = v.next;
            }
            propertyid = p.next;
        }
    }
    Ok(())
}
