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

/// Changes to the previous file.(wasmi)
///
/// 1) Add some third parties or declarations for use.
/// 2) Delete contents about lazy_static: definition of lazy_static SPECDRIVER, functions sgxwasm_init() and wasm_invoke().
/// 3) Define MessageInC in order to pass messages from enclave to app.
/// 4) Change function creat_tx()'s return value by adding two fields: codeid and dataid.
/// 5) Add a function assign_msg_array() to deal with the messages, which is to transfer MessageArray(defined in file third_party/wasmi/src/message.rs) to MessageInC.
/// 6) Change the function ecall_merkle_tree_entry() to transfer messages and related info from enclave to app.
/// 7) Functions about wasmi are moved to the new file "wasmi_encl1.rs".
///    So when calling functions in wasmi_encl1.rs, wasmi_encl1:: should be added in front of a function.

/// Wasmi
#[macro_use]
extern crate lazy_static;
extern crate wasmi;
extern crate sgxwasm;
use std::sync::SgxMutex;
use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};
use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module, NopExternals};
use wasmi::{message_check, args_static};
use wasmi::{Message, TrapKind};
use std::fmt;
use wasmi::{TableInstance, TableRef, FuncInstance, FuncRef, Signature, ModuleImportResolver, ValueType, Trap, RuntimeArgs, Externals};
use std::collections::HashMap;
use wasmi::{MemoryInstance, MemoryRef};
use wasmi::memory_units::Pages;
use std::borrow::BorrowMut;
use core::borrow::Borrow;  

/// Delete lazy_static and SPECDRIVER since two fields Cell<usize> are added and they cannot be 
/// shared between threads safely.

/*
/// Used to get the module instance, lazy_static has a mutex to lock variables when necessary.
lazy_static!{
    static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
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
*/


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

/// Define struct MessageInC.
/// Array others represent 4 fields in the Message struct: func_len, args_len, codeid and dataid, respectively.
#[repr(C)]
pub struct MessageInC {
    pub func: [u8; 100], 
    pub params: [i32; 100], 
    pub others: [i32; 4], 
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
/// Note: Change the return value by adding two fields: codeid and dataid.
fn create_tx(codeproof: *mut MerkleProof, dataproof: *mut MerkleProof,
             wasmfunc_ptr: *mut u8, wasmfunc_len: c_int,
             wasmargs_ptr: *mut i32, wasmargs_len: c_int) -> (String, usize, usize) {
    // Step 1: construct wasmfunc/wasmargs
    let wasmfunc_bytes = unsafe{slice::from_raw_parts(wasmfunc_ptr, wasmfunc_len as usize)};
    let wasmfunc_str = String::from_utf8(wasmfunc_bytes.to_vec()).unwrap();

    let wasmargs_bytes = unsafe{slice::from_raw_parts(wasmargs_ptr, (wasmargs_len/4) as usize)};
    let wasmargs_vec: Vec<i32> = wasmargs_bytes.to_vec();

    // Step 2: get node ID of code&data node
    let codeid = MTGetLeafId(codeproof) as usize;
    let dataid = MTGetLeafId(dataproof) as usize;

    // Step 3: construct Tx
    let tx = format!("TX: codeid: {}, dataid: {}, wasm_func: {}, wasmargs: {:?}", 
                    codeid, dataid, wasmfunc_str, wasmargs_vec);
    println!("[Exec] {}", tx);
    (tx, codeid, dataid)

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

/// Deal with Message Array and pass it to msg_array in App.cpp.
fn assign_msg_array(msg_array: &mut [MessageInC; 100], messageArray: Vec<Message>) {
    let mut index: usize =0;
    for msg_tempt in messageArray {
        if index >= 100 {
            println!("messages are more than 100");
            break;
        }

        let func_l = msg_tempt.func_len;
        let args_l = msg_tempt.args_len;
        let tempt_func = msg_tempt.function;
        let tempt_params = msg_tempt.args;
        let passed_func = tempt_func.as_bytes(); 
        let codeid = msg_tempt.codeid;
        let did = msg_tempt.dataid;

        // func name
        let mut array1 = [0; 100];
        for index_array in 0..passed_func.len() {
            if index_array >= 100 {
                println!("the message's function name's length should be larger than 1000");
                break;
            }
            array1[index_array] = passed_func[index_array];
        }

        // func parameters
        let mut array2 = [-1; 100];
        for index_array in 0..tempt_params.len() {
            if index_array >= 100 {
                println!("the message's function parameters length should be larger than 100");
                break;
            }
            array2[index_array] = tempt_params[index_array];
        }

        let mut array3 = [5; 4];
        array3[0] = func_l as i32;
        array3[1] = args_l  as i32;
        array3[2] = codeid  as i32;
        array3[3] = did  as i32;
        
        let tempt_msg = MessageInC{func: array1, params: array2, others: array3};
        msg_array[index] = tempt_msg;
        index = index + 1;
    }
 
}

/// All the code about wasmi are put in the new file "wasmi_enc1.rs".
/// Change to the previous file: when using function in the wasmi_encl.rs, adding wasmi_enc1:: in front of a function.
/// For example, change run_func to wasmi_enc1::run_func.
mod wasmi_enc1;

/// ecall function, the main entry of the execution enclave
/// Add some steps to transfer messages from enclave to app.
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
    // and get codeid, dataid
    let (tx, codeid, dataid) = create_tx(codeproof, dataproof, wasmfunc_ptr, wasmfunc_len, wasmargs_ptr, wasmargs_len);
    println!("Inside ecall_merkle_tree_entry(): {}", tx);
    println!("codeid is {:?} dataid is {:?}", codeid, dataid);

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

    // Step5.1: run the module and pass the result MessageArray to app
    let messageArray = wasmi_enc1::run_func(&mut code_decrypted, &mut data_decrypted, &wasmfunc_str, wasmargs_vec.clone(), codeid as i32, dataid as i32);
    println!("\n\nInside ecall_merkle_tree_entry(): new memory is {:?}", data_decrypted);
    let tempt_count = messageArray.len() as i32;
    unsafe{ptr::copy_nonoverlapping(&tempt_count as *const c_int, msg_count as *mut c_int, 1)};
    assign_msg_array(msg_array, messageArray);

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

