/*-
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (c) 2022 Rink Springer <rink@rink.nu>
 * For conditions of distribution and use, see LICENSE file
 */
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::env;

use object::elf;
use object::write::StringId;

struct Streamer<'a, R: Read> {
    pub value: u32,
    pub bits_left: usize,
    cursor: &'a mut R,
}

impl<'a, R: Read> Streamer<'a, R> {
    pub fn new(cursor: &'a mut R) -> Self {
        Self{ value: 0, bits_left: 0, cursor }
    }

    fn fill_buffer_and_return_bit(&mut self) -> u32 {
        if let Ok(value) = self.cursor.read_u32::<LittleEndian>() {
            self.value = value >> 1;
            self.bits_left = 31;
            return value & 1
        }

        let mut value: u32 = 0;
        let mut shift: u32 = 0;
        while let Ok(v) = self.cursor.read_u8() {
            value |= (v as u32) << shift;
            shift += 8;
            self.bits_left += 8;
        }
        if self.bits_left == 0 {
            panic!("end of stream");
        }
        self.value = value >> 1;
        self.bits_left -= 1;
        return value & 1
    }

    pub fn read_bits(&mut self, count: u32) -> u32 {
        let mut result: u32 = 0;
        for bit in 0..count {
            let val;
            if self.bits_left == 0 {
                val = self.fill_buffer_and_return_bit();
            } else {
                self.bits_left -= 1;
                val = self.value & 1;
                self.value >>= 1;
            }

            if val != 0 {
                result |= 1 << bit;
            }
        }
        result
    }

    pub fn read_bit(&mut self) -> u32 {
        if self.bits_left != 0 {
            self.bits_left -= 1;
            let value = self.value & 1;
            self.value >>= 1;
            return value
        }
        self.fill_buffer_and_return_bit()
    }

    pub fn drop_bits(&mut self) {
        while (self.bits_left & 7) != 0 {
            self.bits_left -= 1;
            self.value >>= 1;
        }
    }
}

struct Node {
    link: Option<(Box<Node>, Box<Node>)>,
    value: u8,
}

impl Node {
    pub fn new() -> Box<Node> {
        Box::new(Node{ link: None, value: 0 })
    }
}

fn read_tree<R: Read>(streamer: &mut Streamer<R>, depth: u32) -> Box<Node> {
    let mut node = Node::new();

    let bit = streamer.read_bit();
    if bit != 0 {
        node.value = streamer.read_bits(8) as u8;
    } else {
        let first = read_tree(streamer, depth + 1);
        let second = read_tree(streamer, depth + 1);
        node.link = Some((first, second));
    }
    node
}

fn decode_from_tree<R: Read>(streamer: &mut Streamer<R>, tree: &Box<Node>) -> u8 {
    let mut node = tree;
    while !node.link.is_none() {
        let bit = streamer.read_bit();
        node = if bit == 0 { &node.link.as_ref().unwrap().0 } else { &node.link.as_ref().unwrap().1 };
    }
    node.value
}

fn unpack<R: Read>(streamer: &mut Streamer<R>, decompress_len: usize, tree1: &Box<Node>, tree2: &Box<Node>, tree3: &Box<Node>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    while result.len() < decompress_len {
        let v = streamer.read_bit();
        if v != 0 {
            let b1 = decode_from_tree(streamer, tree1);
            result.push(b1);
        } else {
            let b2 = decode_from_tree(streamer, tree2);
            if b2 <= 0xfd {
                let v = streamer.read_bits(5) as u32;
                let b3 = decode_from_tree(streamer, tree3) as u32;

                let delta = (b3 << 5) + v;
                let offset = result.len() - delta as usize;
                for n in 0..b2 {
                    let b = result[offset + n as usize];
                    result.push(b);
                }
            } else {
                if b2 == 0xff {
                    streamer.drop_bits();
                    for _ in 0..8 {
                        let v = streamer.read_bits(8) as u8;
                        result.push(v);
                    }
                    let bl = streamer.read_bits(8);
                    result.push(bl as u8);
                    let bh = streamer.read_bits(8);
                    result.push(bh as u8);
                    let v = streamer.read_bits(8);
                    result.push(v as u8);

                    let n = (v << 16) + (bh << 8) + bl + 1;
                    for _ in 0..n {
                        let v = streamer.read_bits(8) as u8;
                        result.push(v);
                    }
                } else /* b2 != 0xff */ {
                    let b2 = streamer.read_bits(13);

                    let v = streamer.read_bits(5) as u32;
                    let b3 = decode_from_tree(streamer, tree3) as u32;

                    let delta = (b3 << 5) + v;
                    let offset = result.len() - delta as usize;
                    for n in 0..b2 {
                        let b = result[offset + n as usize];
                        result.push(b);
                    }
                }
            }
        }
    }
    result
}

#[derive(Default,Debug)]
pub struct NLMHeader {
    pub magic: [ u8; 24 ],
    pub load_version: u32,
    pub name: [ u8; 14 ],
    pub code_offs: u32,
    pub code_len: u32,
    pub data_offs: u32,
    pub data_len: u32,
    pub uninit_len: u32,
    pub custom_data_offs: u32,
    pub custom_data_len: u32,
    pub autoload_offs: u32,
    pub autoload_len: u32,
    pub fixup_offs: u32,
    pub fixup_len: u32,
    pub externals_offs: u32,
    pub externals_len: u32,
    pub exported_offs: u32,
    pub exported_len: u32,
    pub debug_offs: u32,
    pub debug_len: u32,
    pub start_offs: u32,
    pub term_offs: u32,
    pub check_offs: u32,
    pub nlm_type: u8,
}

impl NLMHeader {
    pub fn new() -> Self {
        Self{ ..Default::default() }
    }

    pub fn from<R: Read>(streamer: &mut R) -> Result<Self, std::io::Error> {
        let mut result = Self::new();

        streamer.read_exact(&mut result.magic)?;
        result.load_version = streamer.read_u32::<LittleEndian>()?;
        streamer.read_exact(&mut result.name)?;
        result.code_offs = streamer.read_u32::<LittleEndian>()?;
        result.code_len = streamer.read_u32::<LittleEndian>()?;
        result.data_offs = streamer.read_u32::<LittleEndian>()?;
        result.data_len = streamer.read_u32::<LittleEndian>()?;
        result.uninit_len = streamer.read_u32::<LittleEndian>()?;
        result.custom_data_offs = streamer.read_u32::<LittleEndian>()?;
        result.custom_data_len = streamer.read_u32::<LittleEndian>()?;
        result.autoload_offs = streamer.read_u32::<LittleEndian>()?;
        result.autoload_len = streamer.read_u32::<LittleEndian>()?;
        result.fixup_offs = streamer.read_u32::<LittleEndian>()?;
        result.fixup_len = streamer.read_u32::<LittleEndian>()?;
        result.externals_offs = streamer.read_u32::<LittleEndian>()?;
        result.externals_len = streamer.read_u32::<LittleEndian>()?;
        result.exported_offs = streamer.read_u32::<LittleEndian>()?;
        result.exported_len = streamer.read_u32::<LittleEndian>()?;
        result.debug_offs = streamer.read_u32::<LittleEndian>()?;
        result.debug_len = streamer.read_u32::<LittleEndian>()?;
        result.start_offs = streamer.read_u32::<LittleEndian>()?;
        result.term_offs = streamer.read_u32::<LittleEndian>()?;
        result.check_offs = streamer.read_u32::<LittleEndian>()?;
        result.nlm_type = streamer.read_u8()?;
        Ok(result)
    }

    pub fn is_magic_valid(&self) -> bool {
        let magic = [
            'N' as u8, 'e' as u8, 't' as u8, 'W' as u8, 'a' as u8, 'r' as u8,
            'e' as u8, ' ' as u8, 'L' as u8, 'o' as u8, 'a' as u8, 'd' as u8,
            'a' as u8, 'b' as u8, 'l' as u8, 'e' as u8, ' ' as u8, 'M' as u8,
            'o' as u8, 'd' as u8, 'u' as u8, 'l' as u8, 'e' as u8, 0x1a as u8 ];
        self.magic == magic
    }
}

#[derive(Debug)]
enum NLMError {
    IoError(std::io::Error),
    InvalidCompression(u8, u8),
}

impl From<std::io::Error> for NLMError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

const NLM_PACKED_OFFSET: usize = 400;

struct NLM {
    pub header: NLMHeader,
    data: Vec<u8>,
}

struct ElfSection<'a> {
    index: object::write::elf::SectionIndex,
    is_code: bool,
    align: usize,
    elf_offset: usize,
    str_id: StringId,
    elf_addr: u64,
    data: &'a [u8],
    rel_str_id: StringId,
    reloc_offset: usize,
    reloc_count: usize,
}

const NLM_CODE_VADDR: u32 = 0x10000000;
const NLM_DATA_VADDR: u32 = 0x40000000;

#[derive(Debug)]
enum NLMFixup {
    AbsRefToDataFromData(u32),
    AbsRefToDataFromCode(u32),
    AbsRefToCodeFromData(u32),
    AbsRefToCodeFromCode(u32),
}

#[derive(Debug)]
enum NLMExternalRef {
    RelRefFromData(u32),
    RelRefFromCode(u32),
    AbsRefFromData(u32),
    AbsRefFromCode(u32),
}

#[derive(Debug)]
struct NLMExternal {
    name: String,
    refs: Vec<NLMExternalRef>,
}

#[derive(Debug)]
enum NLMExport {
    Code(String, u32),
    Data(String, u32),
}

struct ElfSymbol {
    name: StringId,
    index: object::write::elf::SymbolIndex,
    section: Option<object::write::elf::SectionIndex>,
    value: u32,
    info: u8,
}

impl NLM {
    pub fn new(data: &[u8]) -> Result<Self, NLMError> {
        let mut rdr = Cursor::new(&data);
        let header = NLMHeader::from(&mut rdr)?;
        if header.load_version != 0x84 {
            // Not packed; all done
            return Ok(Self{ header, data: data.to_vec() })
        }

        // Skip until the packed payload
        rdr.seek(SeekFrom::Start(NLM_PACKED_OFFSET as u64))?;

        let mut streamer = Streamer::new(&mut rdr);
        let a = streamer.read_bits(8) as u8;
        let b = streamer.read_bits(8) as u8;
        if a != 1 || b != 10 {
            return Err(NLMError::InvalidCompression(a, b));
        }
        let length = streamer.read_bits(32) as usize;

        let tree1 = read_tree(&mut streamer, 0);
        let tree2 = read_tree(&mut streamer, 0);
        let tree3 = read_tree(&mut streamer, 0);
        let unpacked = unpack(&mut streamer, length - NLM_PACKED_OFFSET, &tree1, &tree2, &tree3);

        // Piece together the NLM header and unpacked payload
        let mut unpacked_nlm_data: Vec<u8> = vec![ 0u8; length ];
        unpacked_nlm_data[0..NLM_PACKED_OFFSET].copy_from_slice(&data[0..NLM_PACKED_OFFSET]);
        unpacked_nlm_data[NLM_PACKED_OFFSET..].copy_from_slice(&unpacked);
        unpacked_nlm_data[0x18] = 0x4; // remove compression flag
        Ok(Self{ header, data: unpacked_nlm_data.to_vec() })
    }

    pub fn get_externals(&self) -> Result<Vec<NLMExternal>, NLMError> {
        let mut externals: Vec<NLMExternal> = Vec::new();

        // types in external symbol list:
        // 0  - ? relative reference (near call) from data segment
        // 4  - relative reference (near call) from code segment
        // 8  - ? absolute reference (long offset) from data segment
        // c  - absolute reference (long offset) from code segment
        let offs = self.header.externals_offs as usize;

        let mut rdr = Cursor::new(&self.data[offs..]);
        for _ in 0..self.header.externals_len {
            let name_len = rdr.read_u8()? as usize;
            let mut name = vec! [ 0u8; name_len ];
            rdr.read_exact(&mut name)?;
            let num_relocs = rdr.read_u32::<LittleEndian>()?;
            let name = std::str::from_utf8(&name).unwrap();

            let mut refs: Vec<NLMExternalRef> = Vec::new();
            for _ in 0..num_relocs {
                let val = rdr.read_u32::<LittleEndian>()?;
                let ref_type = val >> 28;
                let ref_val = val & 0x3ffffff;
                let nlm_ref = match ref_type {
                    0x0 => { NLMExternalRef::RelRefFromData(ref_val) },
                    0x4 => { NLMExternalRef::RelRefFromCode(ref_val) },
                    0x8 => { NLMExternalRef::AbsRefFromData(ref_val) },
                    0xc => { NLMExternalRef::AbsRefFromCode(ref_val) },
                    _ => { panic!("unrecognized ref type {:x}", ref_type); }
                };
                refs.push(nlm_ref);
            }

            externals.push(NLMExternal{ name: name.to_string(), refs });
        }
        Ok(externals)
    }

    pub fn get_exports(&self) -> Result<Vec<NLMExport>, NLMError> {
        let mut exports: Vec<NLMExport> = Vec::new();

        let offs = self.header.exported_offs as usize;
        let len = self.header.exported_len as usize;

        let mut rdr = Cursor::new(&self.data[offs..]);
        for _ in 0..len {
            let symbol_len = rdr.read_u8()? as usize;
            let mut symbol = vec! [ 0u8; symbol_len ];
            rdr.read_exact(&mut symbol)?;
            let val = rdr.read_u32::<LittleEndian>()?;
            let symbol = std::str::from_utf8(&symbol).unwrap().to_string();

            let exp_type = val >> 28;
            let exp_val = val & 0x3ffffff;
            let export = match exp_type {
                0x0 => { NLMExport::Data(symbol, exp_val) },
                0x8 => { NLMExport::Code(symbol, exp_val) },
                _ => { panic!("unrecognized export type {:x}", exp_type); }
            };
            exports.push(export);
        }

        Ok(exports)
    }

    pub fn get_fixups(&self) -> Result<Vec<NLMFixup>, NLMError> {
        let mut fixups: Vec<NLMFixup> = Vec::new();

        let offs = self.header.fixup_offs as usize;
        let len = self.header.fixup_len as usize;
        let mut rdr = Cursor::new(&self.data[offs..]);
        for _ in 0..len {
            let val = rdr.read_u32::<LittleEndian>()?;
            let fixup_type = val >> 28;
            let fixup_val = val & 0x3ffffff;
            let fixup = match fixup_type {
                0x0 => { NLMFixup::AbsRefToDataFromData(fixup_val) },
                0x4 => { NLMFixup::AbsRefToDataFromCode(fixup_val) },
                0x8 => { NLMFixup::AbsRefToCodeFromData(fixup_val) },
                0xc => { NLMFixup::AbsRefToCodeFromCode(fixup_val) },
                _ => { panic!("unsupported fixup type {:x}", fixup_type); }
            };
            fixups.push(fixup);
        }

        Ok(fixups)
    }

    pub fn get_autoload(&self) -> Result<Vec<String>, NLMError> {
        let mut autoloads: Vec<String> = Vec::new();

        let mut rdr = Cursor::new(&self.data[self.header.autoload_offs as usize..]);
        for _ in 0..self.header.autoload_len {
            let entry_len = rdr.read_u8()? as usize;
            let mut entry = vec! [ 0u8; entry_len ];
            rdr.read_exact(&mut entry)?;
            let entry = std::str::from_utf8(&entry).unwrap();
            autoloads.push(entry.to_string());
        }

        Ok(autoloads)
    }

    pub fn write_nlm(&self, fname: &str) -> Result<(), std::io::Error> {
        std::fs::write(fname, &self.data)?;
        Ok(())
    }

    pub fn write_elf(&self, fname: &str) -> Result<(), NLMError> {
        let mut nlm_data = self.data.to_vec();
        let fixups = self.get_fixups()?;
        for fixup in &fixups {
            match fixup {
                NLMFixup::AbsRefToDataFromData(data_offset) => {
                    let offset = (*data_offset + self.header.data_offs) as usize;
                    let mut value = LittleEndian::read_u32(&nlm_data[offset..offset + 4]);
                    value += NLM_DATA_VADDR;
                    LittleEndian::write_u32(&mut nlm_data[offset..offset + 4], value);
                },
                NLMFixup::AbsRefToDataFromCode(code_offset) => {
                    let offset = (*code_offset + self.header.code_offs) as usize;
                    let mut value = LittleEndian::read_u32(&nlm_data[offset..offset + 4]);
                    value += NLM_DATA_VADDR;
                    LittleEndian::write_u32(&mut nlm_data[offset..offset + 4], value);
                },
                NLMFixup::AbsRefToCodeFromData(data_offset) => {
                    let offset = (*data_offset + self.header.data_offs) as usize;
                    let mut value = LittleEndian::read_u32(&nlm_data[offset..offset + 4]);
                    value += NLM_CODE_VADDR;
                    LittleEndian::write_u32(&mut nlm_data[offset..offset + 4], value);
                },
                NLMFixup::AbsRefToCodeFromCode(code_offset) => {
                    let offset = (*code_offset + self.header.code_offs) as usize;
                    let mut value = LittleEndian::read_u32(&nlm_data[offset..offset + 4]);
                    value += NLM_CODE_VADDR;
                    LittleEndian::write_u32(&mut nlm_data[offset..offset + 4], value);
                },
            };
        }

        let externals = self.get_externals()?;

        // Count relocations
        let mut num_code_relocations = 0;
        let mut num_data_relocations = 0;
        for ext in &externals {
            for eref in &ext.refs {
                match eref {
                    NLMExternalRef::RelRefFromCode(_) |
                    NLMExternalRef::AbsRefFromCode(_) => {
                        num_code_relocations += 1;
                    },
                    NLMExternalRef::RelRefFromData(_) |
                    NLMExternalRef::AbsRefFromData(_) => {
                        num_data_relocations += 1;
                    }
                }
            }
        }

        let mut out_data = Vec::new();
        let mut writer = object::write::elf::Writer::new(object::Endianness::Little, false, &mut out_data);

        writer.reserve_file_header();

        // Program Header
        writer.reserve_program_headers(2);

        //let _null_index = writer.reserve_section_index();

        let mut sections: Vec<ElfSection> = Vec::new();

        let code_align = 16;
        let code_index = writer.reserve_section_index();
        let code_offset = writer.reserve(self.header.code_len as usize, code_align);
        let code_str_id = writer.add_section_name(b".text");
        writer.reserve_section_index(); // for rel.text
        let code_rel_str_id = writer.add_section_name(b".rel.text");
        let nlm_code_offset = self.header.code_offs as usize;
        let nlm_code_length = self.header.code_len as usize;
        sections.push(ElfSection{
            is_code: true,
            align: code_align,
            index: code_index,
            str_id: code_str_id,
            elf_offset: code_offset,
            elf_addr: NLM_CODE_VADDR as u64,
            data: &nlm_data[nlm_code_offset..nlm_code_offset  + nlm_code_length],
            rel_str_id: code_rel_str_id,
            reloc_count: num_code_relocations,
            reloc_offset: 0, /* filled out later */
        });

        let data_align = 16;
        let data_index = writer.reserve_section_index();
        let data_offset = writer.reserve(self.header.data_len as usize, data_align);
        let data_str_id = writer.add_section_name(b".data");
        writer.reserve_section_index(); // for rel.data
        let data_rel_str_id = writer.add_section_name(b".rel.data");
        let nlm_data_offset = self.header.data_offs as usize;
        let nlm_data_length = self.header.data_len as usize;
        sections.push(ElfSection{
            is_code: false,
            align: data_align,
            index: data_index,
            str_id: data_str_id,
            elf_offset: data_offset,
            elf_addr: NLM_DATA_VADDR as u64,
            data: &nlm_data[nlm_data_offset..nlm_data_offset  + nlm_data_length],
            rel_str_id: data_rel_str_id,
            reloc_count: num_data_relocations,
            reloc_offset: 0, /* filled out later */
        });

        let autoload = self.get_autoload()?;
        let mut autoload_content: Vec<u8> = Vec::new();
        for al in &autoload {
            autoload_content.extend(al.as_bytes());
            autoload_content.push(0u8);
        }

        let autoload_align = 1;
        let _autoload_index = writer.reserve_section_index();
        let autoload_offset = writer.reserve(autoload_content.len(), autoload_align);
        let autoload_str_id = writer.add_section_name(b".nlm.autoload");

        let mut elf_symbols: Vec<ElfSymbol> = Vec::new();
        writer.reserve_null_symbol_index();

        // Collect all local symbols, these are the exported symbols
        let exports = self.get_exports()?;
        for exp in &exports {
            let name = match exp {
                NLMExport::Code(s, _) => { s },
                NLMExport::Data(s, _) => { s },
            };
            let name = writer.add_string(name.as_bytes());
            let section = Some(match exp {
                NLMExport::Code(_, _) => { code_index },
                NLMExport::Data(_, _) => { data_index },
            });
            let value = match exp {
                NLMExport::Code(_, v) => { *v + NLM_CODE_VADDR },
                NLMExport::Data(_, v) => { *v + NLM_DATA_VADDR },
            };
            let index = writer.reserve_symbol_index(section);
            let info = (elf::STB_LOCAL << 4) + elf::STT_FUNC;
            elf_symbols.push(ElfSymbol{ name, index, section, value, info });
        }

        // Add our custom symbols
        let sym_start_name = writer.add_string(b"nlm_start");
        let sym_start_index = writer.reserve_symbol_index(Some(code_index));
        elf_symbols.push(ElfSymbol{ name: sym_start_name, index: sym_start_index, section: Some(code_index), value: self.header.start_offs + NLM_CODE_VADDR, info: (elf::STB_LOCAL << 4) + elf::STT_FUNC });
        let sym_term_name = writer.add_string(b"nlm_terminate");
        let sym_term_index = writer.reserve_symbol_index(Some(code_index));
        elf_symbols.push(ElfSymbol{ name: sym_term_name, index: sym_term_index, section: Some(code_index), value: self.header.term_offs + NLM_CODE_VADDR, info: (elf::STB_LOCAL << 4) + elf::STT_FUNC });
        let sym_check_name = writer.add_string(b"nlm_check");
        let sym_check_index = writer.reserve_symbol_index(Some(code_index));
        elf_symbols.push(ElfSymbol{ name: sym_check_name, index: sym_check_index, section: Some(code_index), value: self.header.check_offs + NLM_CODE_VADDR, info: (elf::STB_LOCAL << 4) + elf::STT_FUNC });

        let symtab_num_local = writer.symbol_count();

        // Now grab the externals, these will be global external symbols
        for ext in &externals {
            let name = writer.add_string(ext.name.as_bytes());
            let index = writer.reserve_symbol_index(None);
            let info = (elf::STB_GLOBAL << 4) + elf::STT_NOTYPE;
            elf_symbols.push(ElfSymbol{ name, index, section: None, value: 0, info });
        }

        // Symbols
        writer.reserve_symtab_section_index();
        writer.reserve_symtab();
        if writer.symtab_shndx_needed() {
            writer.reserve_symtab_shndx_section_index();
        }
        writer.reserve_symtab_shndx();
        writer.reserve_strtab_section_index();
        writer.reserve_strtab();

        // Relocations
        let is_rela = false;
        sections[0].reloc_offset = writer.reserve_relocations(num_code_relocations, is_rela);
        sections[1].reloc_offset = writer.reserve_relocations(num_data_relocations, is_rela);

        // Section headers
        writer.reserve_shstrtab_section_index();
        writer.reserve_shstrtab();
        writer.reserve_section_headers();

        writer.write_file_header(&object::write::elf::FileHeader{
            os_abi: 0,
            e_type: object::elf::ET_DYN,
            abi_version: object::elf::EV_CURRENT,
            e_machine: object::elf::EM_386,
            e_entry: (self.header.start_offs + NLM_CODE_VADDR) as u64,
            e_flags: 0,
        }).unwrap();

        // Program Headers
        writer.write_program_header(&object::write::elf::ProgramHeader{
            p_type: object::elf::PT_LOAD,
            p_align: code_align as u64,
            p_filesz: self.header.code_len as u64,
            p_memsz: self.header.code_len as u64,
            p_offset: code_offset as u64,
            p_flags: object::elf::PF_R | object::elf::PF_X,
            p_paddr: NLM_CODE_VADDR as u64,
            p_vaddr: NLM_CODE_VADDR as u64,
        });
        writer.write_program_header(&object::write::elf::ProgramHeader{
            p_type: object::elf::PT_LOAD,
            p_align: data_align as u64,
            p_filesz: self.header.data_len as u64,
            p_memsz: self.header.data_len as u64,
            p_offset: data_offset as u64,
            p_flags: object::elf::PF_R | object::elf::PF_W,
            p_paddr: NLM_DATA_VADDR as u64,
            p_vaddr: NLM_DATA_VADDR as u64,
        });

        // Section content
        for sh in &sections {
            writer.write_align(sh.align);
            assert_eq!(sh.elf_offset, writer.len());
            writer.write(&sh.data);
        }

        // Autoload section
        writer.write_align(autoload_align);
        writer.write(&autoload_content);

        // Symbols
        writer.write_null_symbol();
        for sym in &elf_symbols {
            //let is_code = sym.section.is_some() && sym.section.unwrap() == code_index;
            //let st_type = if is_code { elf::STT_FUNC } else { elf::STT_COMMON };
            let st_vis = elf::STV_DEFAULT;
            writer.write_symbol(&object::write::elf::Sym{
                name: Some(sym.name),
                section: sym.section,
                st_info: sym.info,
                st_other: st_vis,
                st_shndx: 0,
                st_value: sym.value as u64,
                st_size: 0,
            });
        }

        writer.write_symtab_shndx();
        writer.write_strtab();

        // Relocations, code
        writer.write_align_relocation();
        for (n, ext) in externals.iter().enumerate() {
            for eref in &ext.refs {
                match eref {
                    NLMExternalRef::RelRefFromCode(rel) => {
                        let r_type = elf::R_386_PC32;
                        let r_sym = elf_symbols[symtab_num_local as usize + n - 1].index.0;
                        let r_addend = 0;
                        writer.write_relocation(is_rela, &object::write::elf::Rel{
                            r_offset: (*rel + NLM_CODE_VADDR) as u64,
                            r_sym,
                            r_type,
                            r_addend
                        });
                    },
                    NLMExternalRef::AbsRefFromCode(abs) => {
                        let r_type = elf::R_386_32;
                        let r_sym = elf_symbols[symtab_num_local as usize + n - 1].index.0;
                        let r_addend = 0;
                        writer.write_relocation(is_rela, &object::write::elf::Rel{
                            r_offset: (*abs + NLM_CODE_VADDR) as u64,
                            r_sym,
                            r_type,
                            r_addend
                        });
                    },
                    NLMExternalRef::RelRefFromData(_) | NLMExternalRef::AbsRefFromData(_) => { }
                }
            }
        }

        // Relocations, data
        writer.write_align_relocation();
        for (n, ext) in externals.iter().enumerate() {
            for eref in &ext.refs {
                match eref {
                    NLMExternalRef::RelRefFromCode(_) | NLMExternalRef::AbsRefFromCode(_) => {
                    },
                    NLMExternalRef::RelRefFromData(rel) => {
                        let r_type = elf::R_386_PC32;
                        let r_sym = elf_symbols[symtab_num_local as usize + n - 1].index.0;
                        let r_addend = 0;
                        writer.write_relocation(is_rela, &object::write::elf::Rel{
                            r_offset: (*rel + NLM_DATA_VADDR) as u64,
                            r_sym,
                            r_type,
                            r_addend
                        });
                    },
                    NLMExternalRef::AbsRefFromData(abs) => {
                        let r_type = elf::R_386_32;
                        let r_sym = elf_symbols[symtab_num_local as usize + n - 1].index.0;
                        let r_addend = 0;
                        writer.write_relocation(is_rela, &object::write::elf::Rel{
                            r_offset: (*abs + NLM_DATA_VADDR) as u64,
                            r_sym,
                            r_type,
                            r_addend
                        });
                    }
                }
            }
        }

        writer.write_shstrtab();
        writer.write_null_section_header();
        let symtab_index = writer.symtab_index();

        for sh in &sections {
            let mut sh_flags = object::elf::SHF_ALLOC;
            if sh.is_code {
                sh_flags |= object::elf::SHF_EXECINSTR;
            } else {
                sh_flags |= object::elf::SHF_WRITE;
            }
            writer.write_section_header(&object::write::elf::SectionHeader{
                name: Some(sh.str_id),
                sh_type: object::elf::SHT_PROGBITS,
                sh_flags: sh_flags as u64,
                sh_addr: sh.elf_addr,
                sh_offset: sh.elf_offset as u64,
                sh_size: sh.data.len() as u64,
                sh_link: 0,
                sh_info: 0,
                sh_addralign: sh.align as u64,
                sh_entsize: 0
            });

            writer.write_relocation_section_header(
                sh.rel_str_id,
                sh.index,
                symtab_index,
                sh.reloc_offset,
                sh.reloc_count,
                is_rela,
            );
        }

        writer.write_section_header(&object::write::elf::SectionHeader{
            name: Some(autoload_str_id),
            sh_type: object::elf::SHT_NOTE,
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: autoload_offset as u64,
            sh_size: autoload_content.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: autoload_align as u64,
            sh_entsize: 0
        });

        writer.write_symtab_section_header(symtab_num_local);
        writer.write_symtab_shndx_section_header();
        writer.write_strtab_section_header();
        writer.write_shstrtab_section_header();
        assert_eq!(writer.reserved_len(), writer.len());

        std::fs::write(fname, &out_data)?;
        Ok(())
    }
}

fn main() -> Result<(), NLMError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("usage: {} file.nlm out.elf [out.nlm]", args[0]);
        return Ok(())
    }
    let nlm_fname = &args[1];
    let elf_fname = &args[2];

    let nlm_data = std::fs::read(nlm_fname)?;

    let nlm = NLM::new(&nlm_data)?;

    nlm.write_elf(elf_fname)?;
    if args.len() >= 4 {
        nlm.write_nlm(&args[3])?;
    }
    Ok(())
}
