// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "enclave1"]  // exec enclave
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tcrypto;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_types;
use sgx_types::*;
use sgx_tse::*;

extern crate untrusted;
extern crate itertools;
extern crate attestation;
use attestation::types::*;
use attestation::err::*;
use attestation::func::*;
use std::mem;
use std::ptr;

use std::backtrace::{self, PrintFormat};

//use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use sgx_tcrypto::*;
use sgx_rand::*;

use std::slice;
use std::prelude::v1::*;
use std::sync::Arc;
use std::net::TcpStream;
use std::string::String;
use std::io;
use std::str;
use std::io::{Write, Read, BufReader};
use std::untrusted::fs;
use std::vec::Vec;
use itertools::Itertools;
use std::ffi::CStr;
use std::ffi::CString;
use std::boxed::Box;
use sgx_trts::memeq::ConsttimeMemEq;

/// Wasmi
#[macro_use]
extern crate lazy_static;
extern crate wasmi;
extern crate sgxwasm;
use std::sync::SgxMutex;
use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};
use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module, NopExternals};
use wasmi::{message_check, args_static};
use wasmi::{Message, MessageArray, TrapKind};

/// Get the module, lazy_static has a mutex to lock variables when necessary.
lazy_static!{
    static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
}


fn verify_peer_enclave_trust(peer_enclave_identity: &sgx_dh_session_enclave_identity_t )-> u32 {

    if peer_enclave_identity.isv_prod_id != 0 || peer_enclave_identity.attributes.flags & SGX_FLAGS_INITTED == 0 {
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
        ATTESTATION_STATUS::ENCLAVE_TRUST_ERROR as u32
    } else {
        ATTESTATION_STATUS::SUCCESS as u32
    }
}

#[no_mangle]
pub extern "C" fn test_enclave_init() {
    let cb = Callback{
        verify: verify_peer_enclave_trust,
    };
    init(cb);
}

#[no_mangle]
pub extern "C" fn test_create_session(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t) -> u32 {
    create_session(src_enclave_id, dest_enclave_id) as u32
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn test_close_session(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t) -> u32 {
    close_session(src_enclave_id, dest_enclave_id) as u32
}


pub fn gen_local_report_rust(ti: &sgx_target_info_t, report_data: &sgx_report_data_t) -> sgx_report_t {
    let mut report = sgx_report_t::default();

    let rep = match rsgx_create_report(ti, report_data) {
        Ok(r) =>{
            println!("[Exec]Report creation => success");
            report = r;
            Some(r)
        },
        Err(e) =>{
            println!("[Exec]Report creation => failed {:?}", e);
            None
        },
    };
    report
}


//======================== ported from old exec enclave ==========================//

mod hex;

// MerkleTree
const MAX_LEAF_NODE: i32 = 64;
const MAX_LEN: i32 = 2048;
const MAX_TREE_LEVEL: i32 = 7;
s! {
#[repr(C)]
pub struct Node
{
    pub hash: u32,
    pub lefthash: u32,
    pub righthash: u32,
    pub prefix: c_int,
    pub value: [u8; 2048],

}
#[repr(C)]
pub struct MerkleTree
{

   pub nodes: [Node; 128],
   pub totalLeafNode: c_int, 

}

pub struct MerkleProof 
{

   pub path: [Node; 7],

}

#[repr(C)]
pub struct MessageInC {
    pub func: [u8; 1000],
    pub params: [i32; 100],
}

}

/// serialize node, and calculate the hash
pub fn MTCalNodeHash(node: &Node) -> u32 
{
    let valstr = String::from_utf8(node.value.to_vec()).unwrap();
    let valstr_clean = shrink_string(&valstr);

    let s = format!("L{}R{}P{}V{}", node.lefthash, node.righthash, node.prefix, valstr_clean);    
    let len: usize = s.len();
    let bytes = s.as_bytes();
    let mut hash: u32 = 5381;
        for c in 0..len
        {
            hash = hash * 33 + bytes[c] as u32;
        }
    // println!("MT hash: {:?}", hash);
    hash

}

/// update node hash according to current attributes
pub fn MTUpdateNodeHash(node: &mut Node)
{
    node.hash = MTCalNodeHash(&node);
}


/// check node hash
pub fn MTCheckNodeHash(node: &Node) -> bool
{
        let oldhash = node.hash;
        let newhash = MTCalNodeHash(node);

        // println!("old hash: {} new hash: {} prefix: {}", oldhash, newhash, node.prefix);
        // println!("val: {}", String::from_utf8(node.value.to_vec()).unwrap());
        if oldhash != newhash
        {
                println!("ERROR checking node: old hash: {}, new hash: {}\n", oldhash, newhash);
                return false;
        }
        return true;
}

/// check MerkleProof
pub fn MTCheckMerkleProof(mp: *mut MerkleProof) -> bool
{
    let ref_mut: &mut MerkleProof = unsafe{&mut *mp};
        for i in 0..MAX_TREE_LEVEL 
        {
            if (!MTCheckNodeHash(&ref_mut.path[i as usize])) 
            {
                println!("MTCheckMerkleProof failed");
                return false;
            }
        }
        println!("MTCheckMerkleProof passed");
        return true;
}

/// Serialize MerkleProof into String
pub fn MTSerializeMerkleProof(mp: *const MerkleProof) -> String
{
    let mut ret: String = String::from("MP:");
    let mp_obj: &MerkleProof = unsafe{&*mp};
    let path = &mp_obj.path;

        for i in 0..MAX_TREE_LEVEL 
        {
            let node = &path[i as usize];
            let s = format!("H{}L{}R{}P{}V{:?}", 
                    node.hash, node.lefthash, node.righthash, node.prefix, 
                    shrink_string(&String::from_utf8(node.value.to_vec()).unwrap())); 
            ret = format!("{} {}, {}; ", ret, i, s); 
        }
    println!("MTSerializeMerkleProof finished");
    ret
}

/// generate new ROOT hash based on MerkleProof and new data
pub fn MTGenNewRootHash(mp: *mut MerkleProof, data: &Vec<u8>) -> u32
{
    let mut mp_obj: &mut MerkleProof = unsafe{&mut *mp};
    let mut path = &mut mp_obj.path;

    // write to MerkleProof
    unsafe{ptr::copy_nonoverlapping(data.as_ptr(), path[0].value.as_mut_ptr(), data.len())};
    MTUpdateNodeHash(&mut path[0]);

        for i in 0..(MAX_TREE_LEVEL-1) // [0, MAX_TREE_LEVEL-1)
        {
            let mut node_now = &path[i as usize].clone();
            let mut node_parent = &mut path[(i+1) as usize];
            let prefix_now = node_now.prefix;
            let prefix_parent = node_parent.prefix;

            if prefix_now == prefix_parent*2 // left
            {
                // println!("i: {}, left: {}", i, prefix_now);
                node_parent.lefthash = node_now.hash;
            }
            else // right
            {
                // println!("i: {}, right: {}", i, prefix_now);
                node_parent.righthash = node_now.hash;
            }
            MTUpdateNodeHash(&mut node_parent);
        }
    path[(MAX_TREE_LEVEL-1) as usize].hash
}

/// get the node ID of the leaf node from MerkleProof
pub fn MTGetLeafId(mp: *mut MerkleProof) -> c_int {
    let ref_mut: &mut MerkleProof = unsafe{&mut *mp};
    let leaf = &mut ref_mut.path[0];
    leaf.prefix
}

/// get the value of the leaf node from MerkleProof
pub fn MTGetLeafValue(mp: *mut MerkleProof) -> String {
    let ref_mut: &mut MerkleProof = unsafe{&mut *mp};
    let leaf = &mut ref_mut.path[0];
    shrink_string(&String::from_utf8(leaf.value.to_vec()).unwrap())
}

/// remove trailing `0`s in String
pub fn shrink_string(valstr: &str) -> String
{
    let mut length:i32 = 0;
    // find NUL 
    for item in valstr.as_bytes() {
        if *item == 0 {
            break;
        }
        length += 1;
    }

    String::from_utf8(valstr.as_bytes()[..length as usize].to_vec()).unwrap()
}

/// perform AES-GCM encryption
pub fn aes_gcm_128_encrypt( key: &[u8;16],
                            plaintext: &Vec<u8>,
                            iv: &[u8;12],
                            ciphertext: &mut Vec<u8>,
                            mac: &mut [u8;16]) -> sgx_status_t {

    // println!("aes_gcm_128_encrypt invoked!");

    let plaintext_slice = plaintext.as_slice();
    let ciphertext_slice = &mut ciphertext[..];

    let aad_array: [u8; 0] = [0; 0];
    let mut mac_array: [u8; SGX_AESGCM_MAC_SIZE] = [0; SGX_AESGCM_MAC_SIZE];

    // println!("aes_gcm_128_encrypt parameter prepared! {}, {}",
    //           plaintext_slice.len(),
    //           ciphertext_slice.len());

    let result = rsgx_rijndael128GCM_encrypt(key,
                                             &plaintext_slice,
                                             iv,
                                             &aad_array,
                                             ciphertext_slice,
                                             &mut mac_array);
    // Match the result 
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {
            *mac = mac_array;
        }
    }

    sgx_status_t::SGX_SUCCESS
}

/// perform AES-GCM decryption
pub fn aes_gcm_128_decrypt( key: &[u8;16],
                            ciphertext: &Vec<u8>,
                            iv: &[u8;12],
                            mac: &[u8;16],
                            plaintext: &mut Vec<u8>) -> sgx_status_t {

    // println!("aes_gcm_128_decrypt invoked!");

    let ciphertext_slice = ciphertext.as_slice();
    let plaintext_slice = &mut plaintext[..];

    let aad_array: [u8; 0] = [0; 0];

    // println!("aes_gcm_128_decrypt parameter prepared! {}, {}",
              // plaintext_slice.len(),
              // ciphertext_slice.len());

    let result = rsgx_rijndael128GCM_decrypt(key,
                                             &ciphertext_slice,
                                             iv,
                                             &aad_array,
                                             mac,
                                             plaintext_slice);

    // Match the result 
    match result {
        Err(x) => {
            return x;
        }
        Ok(()) => {}
    }

    sgx_status_t::SGX_SUCCESS
}

/// encrypt & encode
pub fn construct_payload(plaintext: &Vec<u8>) -> String {
    let mut ciphertext: Vec<u8> = vec![0; plaintext.len()];

    let mut payload: Vec<u8> = vec![0; 0]; // iv + mac + ciphertext 

    let key : [u8; 16] = [0; 16];
    let iv : [u8; 12] = [0; 12];
    let mut mac : [u8; 16] = [0; 16];

    aes_gcm_128_encrypt(&key,
                        &plaintext,
                        &iv,
                        &mut ciphertext,
                        &mut mac);

    payload.append(&mut iv.to_vec().clone());
    payload.append(&mut mac.to_vec().clone());
    payload.append(&mut ciphertext.clone());

    // println!("plaintext: {:?} \n ciphertext: {:?} \n MAC: {:?}", plaintext, ciphertext, mac);
    // println!("payload: {:?}", payload);

    hex::encode_hex_no_space(&payload)
}

/// decode & decrypt
pub fn deconstruct_payload(payload: &str) -> Vec<u8> {
    let decoded = hex::decode_hex_no_space(&payload);
    
    let key: [u8; 16] = [0; 16];
    let mut iv2: [u8; 12] = [0; 12];
    let mut mac2: [u8; 16] = [0; 16];
    let mut ciphertext2 = vec![0; decoded.len()-12-16];
    let mut decrypted: Vec<u8> = vec![0; decoded.len()-12-16];

    iv2.clone_from_slice(&decoded[..12]);
    mac2.clone_from_slice(&decoded[12..28]);
    ciphertext2.clone_from_slice(&decoded[28..]);

    aes_gcm_128_decrypt(&key,
                        &ciphertext2,
                        &iv2,
                        &mac2,
                        &mut decrypted);
    decrypted
}

/// create local attestation data: SHA256(oldroot;tx;newroot)
pub fn create_attn_data(oldhash: u32, tx: &str, newhash: u32) -> sgx_report_data_t {
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();

    println!("[Exec]Creating attestation data:");

    // construct SHA256(oldhash;tx;newhash)
    let temp = format!("{};{};{}", oldhash, tx, newhash);
    let result = rsgx_sha256_slice(temp.as_bytes());
    match result {
        Ok(hash) => {
                        println!("SHA256: {:02X}", hash.iter().format("")); 
                        report_data.d[32..].clone_from_slice(&hash);
                    },
        Err(x) => println!("Error {:?}", x),
    }
    // println!("data after encoding: {:?}", hex::encode_hex_no_space(&report_data.d.to_vec()));

    report_data
}

/// create TX string from related arguments
fn create_tx(codeproof: *mut MerkleProof, dataproof: *mut MerkleProof,
             wasmfunc_ptr: *mut u8, wasmfunc_len: c_int,
             wasmargs_ptr: *mut i32, wasmargs_len: c_int) -> String {
    // Step 1: construct wasmfunc/wasmargs
    let wasmfunc_bytes = unsafe{slice::from_raw_parts(wasmfunc_ptr, wasmfunc_len as usize)};
    let wasmfunc_str = String::from_utf8(wasmfunc_bytes.to_vec()).unwrap();

    let wasmargs_bytes = unsafe{slice::from_raw_parts(wasmargs_ptr, (wasmargs_len/4) as usize)};
    let wasmargs_vec: Vec<i32> = wasmargs_bytes.to_vec();

    // Step 2: get node ID of code&data node
    let codeid = MTGetLeafId(codeproof);
    let dataid = MTGetLeafId(dataproof);

    // Step 3: construct Tx
    let tx = format!("TX: codeid: {}, dataid: {}, wasm_func: {}, wasmargs: {:?}", 
                    codeid, dataid, wasmfunc_str, wasmargs_vec);
    println!("[Exec] {}", tx);
    tx

}

/// ecall function, returns the sgx_target_info_t structure to ourside
#[no_mangle]
pub extern "C" fn ecall_get_ti() -> sgx_target_info_t {

    let mut ti: sgx_target_info_t = sgx_target_info_t::default();

    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut report = sgx_report_t::default();

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            println!("Inside ecall_get_ti(): ti generation => success");
            report = r;
            Some(r)
        },
        Err(e) =>{
            println!("Inside ecall_get_ti(): ti generation => failed {:?}", e);
            None
        },
    };

    // copy ti from report_data in 3 steps
    let mut temp_ti:sgx_target_info_t = sgx_target_info_t::default(); 
    
    // copy mr_enclave
    unsafe{
    ptr::copy_nonoverlapping(&(report.body.mr_enclave) as *const sgx_measurement_t, 
                            &mut (temp_ti.mr_enclave) as *mut sgx_measurement_t,
                            1);
    }

    // copy attributes
    unsafe{
    ptr::copy_nonoverlapping(&(report.body.attributes) as *const sgx_attributes_t, 
                            &mut (temp_ti.attributes) as *mut sgx_attributes_t,
                            1);
    }

    // copy misc
    unsafe{
    ptr::copy_nonoverlapping(&(report.body.misc_select) as *const sgx_misc_select_t, 
                            &mut (temp_ti.misc_select) as *mut sgx_misc_select_t,
                            1);
    }
    // println!("mr_enclave copied: {:?}", temp_ti.mr_enclave.m);

    temp_ti
}

/// ecall function, the main entry of the execution enclave
#[no_mangle]
pub extern "C" fn ecall_merkle_tree_entry(codeproof: *mut MerkleProof, dataproof: *mut MerkleProof, 
                                oldhash: u32, report_out: *mut sgx_report_t, 
                                wasmfunc_ptr: *mut u8, wasmfunc_len: c_int,
                                wasmargs_ptr: *mut i32, wasmargs_len: c_int,
                                data_out: *mut u8, tx_out: *mut u8, newhash_ptr: *mut u32,
                                ti: &sgx_target_info_t,
                                msg_array: &mut [MessageInC; 100], msg_count: *mut c_int, msg_size: c_int) -> sgx_status_t { 

    // Step 1: check MerkleProof of code/data
    if !MTCheckMerkleProof(codeproof) || !MTCheckMerkleProof(dataproof)
    {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    // Step 2: create transaction (for step 7)
    let tx = create_tx(codeproof, dataproof, wasmfunc_ptr, wasmfunc_len, wasmargs_ptr, wasmargs_len);
    println!("Inside ecall_merkle_tree_entry(): {}", tx);

    // Step 3: get the value of the code/data nodes (leaf node)
    let code_val = MTGetLeafValue(codeproof);
    println!("Inside ecall_merkle_tree_entry(): code_val: {} len: {} ", 
            code_val, code_val.len());

    let data_val = MTGetLeafValue(dataproof);
    println!("Inside ecall_merkle_tree_entry(): data_val: {} len: {} ", 
            data_val, data_val.len());

    // Step 4: decode & decrypt (code/data nodes)
    let mut code_decrypted = deconstruct_payload(&code_val.as_str());
    let mut data_decrypted = deconstruct_payload(&data_val.as_str());

    // Step 5: pass code/data to wasmi and run
    let wasmfunc_bytes = unsafe{slice::from_raw_parts(wasmfunc_ptr, wasmfunc_len as usize)};
    let wasmfunc_str = String::from_utf8(wasmfunc_bytes.to_vec()).unwrap();

    let wasmargs_bytes = unsafe{slice::from_raw_parts(wasmargs_ptr, (wasmargs_len/4) as usize)};
    let wasmargs_vec: Vec<i32> = wasmargs_bytes.to_vec();
    println!("\n\nInside ecall_merkle_tree_entry(): oldhash {}, wasmfunc: {:?}, wasmargs: {:?}", 
            oldhash, wasmfunc_str, wasmargs_vec);

    //pass messages to app here

    //tempt replace of real run function
    //let messageArray = run_dfinity_with_export_memory(&mut code_decrypted, &mut data_decrypted, &wasmfunc_str, wasmargs_vec.clone());
    // for test, let data_buf(data_decrypted) 
    let messageArray = dfinity_code_run();
    // println!("\n\nInside ecall_merkle_tree_entry(): new memory is {:?}", data_decrypted);

    println!("message will be passed are {:?}", messageArray);
    println!("message number is {:?}", messageArray.length());
    let tempt_count = messageArray.length() as i32;
    unsafe{ptr::copy_nonoverlapping(&tempt_count as *const c_int, msg_count as *mut c_int, 1)};

    let mut index: usize =0;
    for msg_tempt in messageArray.msgArray {
        let tempt_func = msg_tempt.function.unwrap();
        let tempt_params = msg_tempt.args;
        let passed_func_str = format!("{:?}", tempt_func);
        let passed_func = passed_func_str.as_bytes(); 
        println!("passed_func_str is {:?}", passed_func_str);

        let mut array1 = [0; 1000];
        for index_array in 0..passed_func.len() {
            if index_array >= 1000 {
                println!("the message's function length should be larger than 1000");
                break;
            }
            array1[index_array] = passed_func[index_array];
        }
        println!("array1 is {:?}", array1.to_vec());

        let mut array2 = [-1; 100];
        for index_array in 0..tempt_params.len() {
            if index_array >= 100 {
                println!("the message's function parameters length should be larger than 100");
                break;
            }
            array2[index_array] = tempt_params[index_array];
        }
        println!("array2 is {:?}", array2.to_vec());

        let tempt_msg = MessageInC{func: array1, params: array2};
        println!("tempt_msg is {:?} {:?}", tempt_msg.func.to_vec(), tempt_msg.params.to_vec());
        if index >= 100 {
            println!("messages are more than 100");
            break;
        }
        msg_array[index] = tempt_msg;
        index = index + 1;
        println!("func and params in every message is {:?} {:?}",tempt_func, tempt_params );
    }
    //unsafe{ptr::copy_nonoverlapping(new_data.as_ptr(), data_out, new_data.len())};

    // Step 6: generate new ROOT inside the enclave
    let new_data = construct_payload(&data_decrypted);
    let mut newroot = MTGenNewRootHash(dataproof, &new_data.as_bytes().to_vec());
    println!("Inside ecall_merkle_tree_entry(): new ROOT hash: {:?}", newroot);

    // Step 7: create attestation data([..32]: 0; [32..]: SHA256(oldhash;tx;newhash))
    let attn_data = create_attn_data(oldhash, &tx, newroot);

    // Step 8: generate attn report
    let new_report = gen_local_report_rust(&ti, &attn_data);
    unsafe{
    ptr::copy_nonoverlapping(&new_report as *const sgx_report_t, 
                             report_out as *mut sgx_report_t,
                            1);
    }

    // Step 9: prepare outputs

    // Step 9.1: prepare data_out
    println!("Inside ecall_merkle_tree_entry(): data_out: {}", new_data);
    unsafe{ptr::copy_nonoverlapping(new_data.as_ptr(), data_out, new_data.len())};

    // Step 9.2: prepare tx_out
    println!("Inside ecall_merkle_tree_entry(): tx_out: {}", tx);
    unsafe{ptr::copy_nonoverlapping(tx.as_ptr(), tx_out, tx.len())};

    // Step 9.3: prepare newhash_ptr
    println!("Inside ecall_merkle_tree_entry(): newhash: {}", newroot);
    unsafe{ptr::copy_nonoverlapping(&newroot as *const u32, newhash_ptr as *mut u32, 1)};

    sgx_status_t::SGX_SUCCESS

}


/// Wasmi
/// Add some use declarations.
use std::fmt;
use wasmi::{TableInstance, TableRef, FuncInstance, FuncRef, Signature, ModuleImportResolver, ValueType, Trap, RuntimeArgs, Externals};
use std::collections::HashMap;
use wasmi::{MemoryInstance, MemoryRef};
use wasmi::memory_units::Pages;
use std::borrow::BorrowMut;

/// Struct DfinityFunc is used when the wast file containing import func's internalize and externalize functions.
/// Field table represents the given module's table, which will be used in the two imported functions.
/// Field funcmap is used to store the (index, funcRef) key-value relationship.
/// Field counter is used to assign a funcRef's index.
#[derive(Clone)]
pub struct DfinityFunc {
    pub table: Option<TableRef>,
    pub funcmap: HashMap<i32, Option<FuncRef>>,
    pub counter: i32,
}

impl fmt::Debug for DfinityFunc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DfinityData")
            .field("table", &self.table)
            .field("funcmap", &self.funcmap)
            .field("counter", &self.counter)
            .finish()
    }
}

impl DfinityFunc {
    fn new() -> DfinityFunc {
        DfinityFunc {
            table: Some(TableInstance::alloc(1, None).unwrap()),
            funcmap: HashMap::new(),
            counter: 0,
        }
    }
}

/// Define the two imported functions' index.
const FUNC_EXTERNALIZE: usize = 0;
const FUNC_INTERNALIZE: usize = 1;

/// Implement struct DfinityFunc's trait Externals.
/// Actually, this trait is to realize functions internalize and externalize.
/// Function externalize loads a function in table into the funcmap.
/// Function internalize does the opposite thing.
impl Externals for DfinityFunc {
    fn invoke_index(&mut self, index: usize, args: RuntimeArgs) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            FUNC_EXTERNALIZE => {
                let a: u32 = args.nth(0);
                let table = self.table.as_ref().expect("Function 'func_externalize' expects attached table",);
                // should check whether this function has return value or not
                // Only need to check this in externalize function
                let func = table.get(a).unwrap();
                let mut func_map = self.funcmap.borrow_mut();
                let func_counter = self.counter;
                func_map.insert(func_counter, func);
                self.counter = func_counter + 1;
                let result = Some(RuntimeValue::I32(func_counter));

                Ok(result)
            }
            FUNC_INTERNALIZE => {
                let a: u32 = args.nth(0);
                let b: i32 = args.nth(1); 
                let table = self.table.as_ref().expect("Function 'func_internalize' expects attached table",);
                let func = self.funcmap.get(&b).unwrap().clone();
                table.set(a, func);

                Ok(None)
            }
            _ => panic!("env doesn't provide function at index {}", index),
        }
    }
}

/// Implement function check_signature() in the struct DfinityFunc.
/// This function is used to check whether a function's siganature equals to its predefined type or not.
impl DfinityFunc {
    fn check_signature(&self, index: usize, signature: &Signature) -> bool {

        let (params, ret_ty): (&[ValueType], Option<ValueType>) = match index {
            FUNC_EXTERNALIZE => (&[ValueType::I32], Some(ValueType::I32)),
            FUNC_INTERNALIZE => (&[ValueType::I32, ValueType::I32], None),
            _ => return false,
        };

        signature.params() == params && signature.return_type() == ret_ty
    }
}

/// Implement trait ModuleImportResolver for struct DfinityFunc.
impl ModuleImportResolver for DfinityFunc {
    fn resolve_func(&self, field_name: &str, signature: &Signature) -> Result<FuncRef, InterpreterError> {
        let index = match field_name {
            "externalize" => FUNC_EXTERNALIZE,
            "internalize" => FUNC_INTERNALIZE,
            _ => {
                return Err(InterpreterError::Instantiation(
                    format!("Export {} not found", field_name),
                ))
            }
        };

        if !self.check_signature(index, signature) {
            return Err(InterpreterError::Instantiation(format!(
                "Export `{}` doesnt match expected type {:?}",
                field_name,
                signature
            )));
        }

        Ok(FuncInstance::alloc_host(signature.clone(), index))
    }
}

/// Struct DfinityData is used when the wast file containing import data's internalize, externalize and len functions.
/// Field memory represents the given module's memory, which will be used in the two imported functions.
/// Field datamap is used to store the (index, databuf) key-value relationship.
/// Field counter is used to assign a databuf's index.
#[derive(Clone)]
pub struct DfinityData {
    pub memory: Option<MemoryRef>,
    pub datamap: HashMap<i32, Vec<u8>>,
    pub counter: i32,
}

impl fmt::Debug for DfinityData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DfinityData")
            .field("memory", &self.memory)
            .field("datamap", &self.datamap)
            .field("counter", &self.counter)
            .finish()
    }
}

impl DfinityData {
    fn new() -> DfinityData {
        DfinityData {
            memory: Some(MemoryInstance::alloc(Pages(1), None).unwrap()),
            datamap: HashMap::new(),
            counter: 0,
        }
    }
}

/// Define the three imported functions' index.
const DATA_EXTERNALIZE: usize = 0;
const DATA_INTERNALIZE: usize = 1;
const DATA_LENGTH: usize = 2;

/// Implement struct DfinityData's trait Externals.
/// Actually, this trait is to realize functions internalize, externalize and len.
/// Function externalize loads a databuf(some region in the module's memory) in table into the datamap.
/// Function internalize does the opposite thing.
/// Function len is to get a databuf's length.
impl Externals for DfinityData {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {
        match index {
            DATA_EXTERNALIZE => {
                let a: u32 = args.nth(0);
                let b: i32 = args.nth(1);
                let memory = self.memory.as_ref().expect("Function 'data_externalize' expects attached memory",);
                let buf = memory.get(a, b as usize).expect("Successfully retrieve the result");
                let mut data_map = self.datamap.borrow_mut();
                let data_counter = self.counter;
                data_map.insert(data_counter, buf.to_vec());
                self.counter = data_counter + 1;
                let result = Some(RuntimeValue::I32(data_counter));

                Ok(result)
            }
            DATA_INTERNALIZE => {
                let a: i32 = args.nth(0);
                let b: i32 = args.nth(1);
                let c: i32 = args.nth(2);
                let d: i32 = args.nth(3); 
                let memory = self.memory.as_ref().expect("Function 'data_internalize' expects attached memory",);
                let mut data_map = self.datamap.borrow_mut();
                let buffer = data_map.get(&c);
                let mem = MemoryInstance::alloc(Pages(1), None).unwrap();
                mem.set(0, &buffer.unwrap()).expect("Successful initialize the memory");
                MemoryInstance::transfer(&mem, d as usize, &memory, a as usize, b as usize).unwrap();

                Ok(None)
            }
            DATA_LENGTH => {
                let a: i32 = args.nth(0);
                let mut data_map = self.datamap.borrow_mut();
                let buffer = data_map.get(&a);
                let length = buffer.unwrap().len();
                let i32length: i32 = length as i32;
        
                Ok(Some(RuntimeValue::I32(i32length)))
            }
            _ => panic!("env doesn't provide function at index {}", index),
        }
    }
}

/// Implement function check_signature() in the struct DfinityData.
/// This function is used to check whether a function's siganature equals to its predefined type or not.
impl DfinityData {
    fn check_signature(&self, index: usize, signature: &Signature) -> bool {

        let (params, ret_ty): (&[ValueType], Option<ValueType>) = match index {
            DATA_EXTERNALIZE => (&[ValueType::I32, ValueType::I32], Some(ValueType::I32)),
            DATA_INTERNALIZE => (&[ValueType::I32, ValueType::I32, ValueType::I32, ValueType::I32], None),
            DATA_LENGTH => (&[ValueType::I32], Some(ValueType::I32)),
            _ => return false,
        };

        signature.params() == params && signature.return_type() == ret_ty
    }
}

/// Implement trait ModuleImportResolver for struct DfinityData.
impl ModuleImportResolver for DfinityData {
    fn resolve_func(&self, field_name: &str, signature: &Signature) -> Result<FuncRef, InterpreterError> {
        let index = match field_name {
            "externalize" => DATA_EXTERNALIZE,
            "internalize" => DATA_INTERNALIZE,
            "length" => DATA_LENGTH,
            _ => {
                return Err(InterpreterError::Instantiation(
                    format!("Export {} not found", field_name),
                ))
            }
        };

        if !self.check_signature(index, signature) {
            return Err(InterpreterError::Instantiation(format!(
                "Export `{}` doesnt match expected type {:?}",
                field_name,
                signature
            )));
        }

        Ok(FuncInstance::alloc_host(signature.clone(), index))
    }
}

#[no_mangle]
pub extern "C"
fn sgxwasm_init() -> sgx_status_t {
    let mut sd = SPECDRIVER.lock().unwrap();
    *sd = SpecDriver::new();
    sgx_status_t::SGX_SUCCESS
}

fn wasm_invoke(module : Option<String>, field : String, args : Vec<RuntimeValue>)
              -> Result<Option<RuntimeValue>, InterpreterError> {
    let mut program = SPECDRIVER.lock().unwrap();
    let module = program.module_or_last(module.as_ref().map(|x| x.as_ref()))
                        .expect(&format!("Expected program to have loaded module {:?}", module));
    module.invoke_export(&field, &args, program.spec_module())
}

/// Execute dfinity_data.wast file.
///
/// Workflow is as follows:
/// Step1: instantiate the module from buffer(bytecode) directly and form a parity module.
/// Step2: new a mut struct DfinityFunc and DfinityData.
/// Step3: transfer the parity module to a module in wasmi.
/// Step4: add data field to the module's memory.
/// Step5: before before invoking the function, get the module's exported memory and assign it to the struct's memory field.
/// Step6: invoke the function with the given function name and its parameters.
/// Step7: get messages if any. If message_check equals -1, this means there is no message; else the message_check represents the func index in the table.
/// Step8: get the revised memory(also is known as data), and assign it to the return result.
///        actually, the wast file that does not contain func struct will not produce any new message, so the messageArray is empty.
fn run_data(code: &mut Vec<u8>, data_buf: &mut Vec<u8>, wasm_func: &str, wasm_args: Vec<i32>) -> MessageArray {
    let module = wasmi::Module::from_buffer(&code).unwrap();
    let mut func = DfinityFunc::new();
    let mut data = DfinityData::new();
    let instance = ModuleInstance::new(&module, &ImportsBuilder::new().with_resolver("data", &data),).expect("Failed to instantiate module").assert_no_start();
    let memory = instance.memory_by_index(0).expect("this is the memory of this instance");
    memory.set(0, &data_buf);
    let internal_mem = instance.export_by_name("memory").expect("Module expected to have 'memory' export").as_memory().cloned().expect("'memory' export should be a memory");
    data.memory = Some(internal_mem);
    let mut args : Vec<RuntimeValue> = Vec::new();
    for argument in wasm_args {
        let temp_arg = RuntimeValue::I32(argument);
        args.push(temp_arg);
    }
    instance.invoke_export(wasm_func, &mut args, &mut data).expect("");
    
    let mut messageArray = MessageArray::new();
    let mut message_bool :i32 = -1;
    let mut args :Vec<i32> = Vec::new();
    unsafe {
        for tempt_str in args_static.split("+") {
            if tempt_str != "" {
                args.push(tempt_str.parse::<i32>().unwrap());
            }
        }
        message_bool = message_check;
    }
    args.reverse();
    if message_bool != -1 {
        let func_ref = func.clone().table.unwrap().get(message_bool as u32).map_err(|_| TrapKind::TableAccessOutOfBounds);
        let temptMessage = Message::new(func_ref.unwrap(), args);
        messageArray.push(temptMessage);
    }

    data_buf.truncate(0);
    let revised_memory = instance.memory_by_index(0).unwrap().get_whole_buf().unwrap();
    data_buf.extend(revised_memory.iter().cloned());
    messageArray
}

/// Execute dfinity_func.wast file.
///
/// Workflow is as follows:
/// Step1: instantiate the module from buffer(bytecode) directly and form a parity module.
/// Step2: new a mut struct DfinityFunc and DfinityData.
/// Step3: transfer the parity module to a module in wasmi.
/// Step4: add data field to the module's memory.
/// Step5: before before invoking the function, get the module's exported table and assign it to the struct's table field.
/// Step6: invoke the function with the given function name and its parameters.
/// Step7: get messages if any. If message_check equals -1, this means there is no message; else the message_check represents the func index in the table.
/// Step8: get the revised memory(also is known as data), and assign it to the return result.
///        in this wast file, the module calls its own function, so no new message will be produced and the messageArray will be empty.
fn run_func_without_msg(code: &mut Vec<u8>, data_buf: &mut Vec<u8>, wasm_func: &str, wasm_args: Vec<i32>) -> MessageArray {
    let module = wasmi::Module::from_buffer(&code).unwrap();

    let mut func = DfinityFunc::new();

    let instance = ModuleInstance::new(
        &module,
        &ImportsBuilder::new().with_resolver("func", &func),
    ).expect("Failed to instantiate module")
        .assert_no_start();
    
    let memory = instance.memory_by_index(0).expect("this is the memory of this instance");
    memory.set(0, &data_buf);

    let internal_table = instance
        .export_by_name("table")
        .expect("Module expected to have 'table' export")
        .as_table()
        .cloned()
        .expect("'table' export should be a table"); 
    func.table = Some(internal_table);
    
    let mut args : Vec<RuntimeValue> = Vec::new();
    for argument in wasm_args {
        let temp_arg = RuntimeValue::I32(argument);
        args.push(temp_arg);
    }
    instance.invoke_export(wasm_func, &mut args, &mut func).expect("");

    let mut messageArray = MessageArray::new();
    let mut message_bool :i32 = -1;
    let mut args :Vec<i32> = Vec::new();
    unsafe {
        for tempt_str in args_static.split("+") {
            if tempt_str != "" {
                args.push(tempt_str.parse::<i32>().unwrap());
            }
        }
        message_bool = message_check;
    }
    args.reverse();
    if message_bool != -1 {
        let func_ref = func.clone().table.unwrap().get(message_bool as u32).map_err(|_| TrapKind::TableAccessOutOfBounds);
        let temptMessage = Message::new(func_ref.unwrap(), args);
        messageArray.push(temptMessage);
    }

    data_buf.truncate(0);
    let revised_memory = instance.memory_by_index(0).unwrap().get_whole_buf().unwrap();
    data_buf.extend(revised_memory.iter().cloned());
    messageArray
}

/// Execute module1.wast file with corresponding module2.wast. (Called function does not have params.)
/// Or execute module4.wast file with corresponding module5.wast. (Called function have params.)
///
/// Workflow is as follows:
/// Step1: instantiate the module from buffer(bytecode) directly and form a parity module.
/// Step2: new a mut struct DfinityFunc and DfinityData.
/// Step3: transfer the parity module to a module in wasmi.
/// Step4: add data field to the module's memory.
/// Step5: before before invoking the function, get the module's exported table and assign it to the struct's table field.
/// Extra step: instantiate a new module(module2.wast) which contains a function store() that will be called in module1.
/// Step6: invoke the function with the given function name and its parameters.
/// Step7: get messages if any. If message_check equals -1, this means there is no message; else the message_check represents the func index in the table.
/// Step8: get the revised memory(also is known as data), and assign it to the return result.
///             Thus, a new message will be produced in module1's messageArray.
fn run_func_with_msg(code: &mut Vec<u8>, data_buf: &mut Vec<u8>, wasm_func: &str, wasm_args: Vec<i32>) -> MessageArray {
    let module = wasmi::Module::from_buffer(&code).unwrap();
    let mut func = DfinityFunc::new();

    let instance = ModuleInstance::new(
        &module,
        &ImportsBuilder::new().with_resolver("func", &func),
    ).expect("Failed to instantiate module")
        .assert_no_start();
    
    let memory = instance.memory_by_index(0).expect("this is the memory of this instance");
    //let data_buf = data_str.as_bytes();
    memory.set(0, &data_buf);

    let internal_table = instance
        .export_by_name("table")
        .expect("Module expected to have 'table' export")
        .as_table()
        .cloned()
        .expect("'table' export should be a table"); 
    func.table = Some(internal_table);
    
    let mut args : Vec<RuntimeValue> = Vec::new();
    for argument in wasm_args {
        let temp_arg = RuntimeValue::I32(argument);
        args.push(temp_arg);
    }
    
    // module2.wast
    // let mut code2: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00, 0x04, 0x04, 0x01, 0x70, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x7f, 0x0b, 0x07, 0x09, 0x01, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x01, 0x00, 0x09, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x00, 0x0a, 0x08, 0x01, 0x06, 0x00, 0x41, 0x06, 0x24, 0x00, 0x0b].to_vec();
    // module4.wast
    let mut code2: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x01, 0x7f, 0x00, 0x03, 0x02, 0x01, 0x00, 0x04, 0x04, 0x01, 0x70, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x7f, 0x0b, 0x07, 0x09, 0x01, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x01, 0x00, 0x09, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x00, 0x0a, 0x0b, 0x01, 0x09, 0x00, 0x20, 0x00, 0x41, 0x01, 0x6a, 0x24, 0x00, 0x0b].to_vec();
    let module2 = wasmi::Module::from_buffer(&code2).unwrap();
    let mut func2 = DfinityFunc::new();
    let instance2 = ModuleInstance::new(&module2,&ImportsBuilder::new().with_resolver("func", &func2),).expect("Failed to instantiate module").assert_no_start();
    let internal_table2 = instance2.export_by_name("table").expect("Module expected to have 'table' export").as_table().cloned().expect("'table' export should be a table"); 
    func2.table = Some(internal_table2);
    let func_table2 = func2.table.as_ref().expect("Module2's table is needed to get the function store.",);
    let func_temp = func_table2.get(0).unwrap(); 
    func.funcmap.insert(0, func_temp);

    instance.invoke_export(wasm_func, &mut args, &mut func).expect("");

    let mut messageArray = MessageArray::new();
    let mut message_bool :i32 = -1;
    let mut args :Vec<i32> = Vec::new();
    unsafe {
        for tempt_str in args_static.split("+") {
            if tempt_str != "" {
                args.push(tempt_str.parse::<i32>().unwrap());
            }
        }
        message_bool = message_check;
    }
    args.reverse();
    if message_bool != -1 {
        let func_ref = func.clone().table.unwrap().get(message_bool as u32).map_err(|_| TrapKind::TableAccessOutOfBounds);
        let temptMessage = Message::new(func_ref.unwrap(), args);
        messageArray.push(temptMessage);
    }
    println!("message array is {:?}", messageArray);

    // assign data_buf new memory buf
    //data_buf = &mut instance.memory_by_index(0).unwrap().get_whole_buf().unwrap();
    messageArray
}

/// This function is a ECALL, which is used to test the execution of wasm outside enclave.
#[no_mangle]
pub extern "C" fn dfinity_code_run() -> MessageArray {
/*   
    // Example for DfinityData
    let mut data_buf = "Hi DFINITY".as_bytes().to_vec();
    
    //for DfinityData dfinity_data.wast
    let mut wasm_binary: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x05, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x00, 0x02, 0x35, 0x03, 0x04, 0x64, 0x61, 0x74, 0x61, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x00, 0x04, 0x64, 0x61, 0x74, 0x61, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x04, 0x64, 0x61, 0x74, 0x61, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x02, 0x03, 0x04, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x7e, 0x0b, 0x07, 0x1e, 0x04, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x04, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x03, 0x03, 0x73, 0x65, 0x74, 0x00, 0x04, 0x04, 0x70, 0x65, 0x65, 0x6b, 0x00, 0x05, 0x0a, 0x30, 0x03, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x24, 0x00, 0x0b, 0x06, 0x00, 0x20, 0x00, 0x24, 0x00, 0x0b, 0x1c, 0x00, 0x41, 0x00, 0x41, 0x0a, 0x10, 0x03, 0x41, 0x0a, 0x23, 0x00, 0x10, 0x02, 0x23, 0x00, 0x41, 0x00, 0x10, 0x01, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x24, 0x00, 0x0b].to_vec();
    let wasm_func = "peek"; //the function name can be "peek"
    let mut wasm_args: Vec<i32> = Vec::new();
    wasm_args.push(0 as i32);
    wasm_args.push(10 as i32);

    println!("before invoking function, memory (not envised data) is {:?}", data_buf);
    let messageArray = run_data(&mut wasm_binary, &mut data_buf, wasm_func, wasm_args);
    println!("after invoking function, memory (envised data) is {:?}", data_buf);
    messageArray
*/

/*
    // Example1 for DfinityFunc: this example shows call_indirect functioing correctly, which means it calls functions in its own module
    //for DfinityFunc func_ex.wast
    let mut data_buf = "Hi DFINITY FUNC EXAMPLE1".as_bytes().to_vec();
    let mut wasm_binary: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x04, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x02, 0x27, 0x02, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x03, 0x03, 0x03, 0x02, 0x02, 0x02, 0x04, 0x04, 0x01, 0x70, 0x00, 0x02, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x1e, 0x03, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x01, 0x00, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x09, 0x63, 0x61, 0x6c, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x03, 0x09, 0x07, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x01, 0x02, 0x0a, 0x1e, 0x02, 0x06, 0x00, 0x41, 0x11, 0x24, 0x00, 0x0b, 0x15, 0x01, 0x01, 0x7f, 0x41, 0x00, 0x10, 0x01, 0x21, 0x00, 0x41, 0x01, 0x20, 0x00, 0x10, 0x00, 0x41, 0x01, 0x11, 0x02, 0x00, 0x0b].to_vec();
    let wasm_func = "callstore";
    let mut wasm_args: Vec<i32> = Vec::new();

    println!("before invoking function, memory (not envised data) is {:?}", data_buf);
    let messageArray = run_func_without_msg(&mut wasm_binary, &mut data_buf, wasm_func, wasm_args);
    println!("after invoking function, memory (envised data) is {:?}", data_buf);
    messageArray
*/

/*
    // Example2 for DfinityFunc: this example shows call_indirect producing a message, which means it calls functions not in its own module
    // for module1.wast and module2.wast. The tested function has no params.
    let mut data_buf = "Hi DFINITY FUNC EXAMPLE2".as_bytes().to_vec();
    let mut wasm_binary: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x04, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x02, 0x27, 0x02, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x03, 0x03, 0x03, 0x02, 0x02, 0x02, 0x04, 0x04, 0x01, 0x70, 0x00, 0x02, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x1e, 0x03, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x01, 0x00, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x09, 0x63, 0x61, 0x6c, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x03, 0x0a, 0x16, 0x02, 0x06, 0x00, 0x41, 0x11, 0x24, 0x00, 0x0b, 0x0d, 0x00, 0x41, 0x00, 0x41, 0x00, 0x10, 0x00, 0x41, 0x00, 0x11, 0x02, 0x00, 0x0b].to_vec();
    let wasm_func = "callstore";
    let mut wasm_args: Vec<i32> = Vec::new();
    
    println!("before invoking function, memory (not envised data) is {:?}", data_buf);
    let messageArray = run_func_with_msg(&mut wasm_binary, &mut data_buf, wasm_func, wasm_args);
    println!("after invoking function, memory (envised data) is {:?}", data_buf);
    messageArray
*/

    // Example3 for DfinityFunc: this example shows call_indirect producing a message, which means it calls functions not in its own module
    // for module1.wast and module2.wast. The tested function has one param.
    let mut data_buf = "Hi DFINITY FUNC EXAMPLE3".as_bytes().to_vec();
    let mut wasm_binary: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x13, 0x04, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x02, 0x27, 0x02, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x03, 0x03, 0x02, 0x01, 0x00, 0x04, 0x04, 0x01, 0x70, 0x00, 0x02, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x1e, 0x03, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x01, 0x00, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x09, 0x63, 0x61, 0x6c, 0x6c, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x00, 0x02, 0x0a, 0x11, 0x01, 0x0f, 0x00, 0x41, 0x00, 0x41, 0x00, 0x10, 0x00, 0x20, 0x00, 0x41, 0x00, 0x11, 0x02, 0x00, 0x0b].to_vec();
    let wasm_func = "callstore";
    let mut wasm_args: Vec<i32> = Vec::new();
    wasm_args.push(2 as i32);

    println!("before invoking function, memory (not envised data) is {:?}", data_buf);
    let messageArray = run_func_with_msg(&mut wasm_binary, &mut data_buf, wasm_func, wasm_args);
    println!("after invoking function, memory (envised data) is {:?}", data_buf);
    messageArray
}