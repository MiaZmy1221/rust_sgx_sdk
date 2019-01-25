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
use attestation::*;
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

mod hex;

#[macro_use]
extern crate lazy_static;
extern crate wasmi;
extern crate sgxwasm;
use wasmi::Message;
mod wasmi_plugin;

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
    let mut key: sgx_key_128bit_t = sgx_key_128bit_t::default(); // Session Key
    let ret = create_session(src_enclave_id, dest_enclave_id, &mut key) as u32;
    src_session_key_insert(&dest_enclave_id, &key);
    src_session_key_print();
    ret
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn test_close_session(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t) -> u32 {
    let ret = close_session(src_enclave_id, dest_enclave_id) as u32;
    src_session_key_remove(&dest_enclave_id);
    ret
}

#[no_mangle]
pub extern "C" fn test_generate_request(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t,
                                    node_idx: c_int, payload_out: *mut u8, payload_len: c_int) -> sgx_status_t {
    let session_key: sgx_key_128bit_t = src_session_key_get(&dest_enclave_id); // Session Key
    let mut plaintext = format!("{}", node_idx);
    let encrypted = construct_payload(&plaintext.as_bytes().to_vec(), &session_key);
    println!("encrypted: {:?}", encrypted);
    let bytes = encrypted.as_bytes();
    unsafe{ptr::copy_nonoverlapping(bytes.as_ptr(), payload_out, bytes.len())};
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn test_get_key_from_response(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t,
                                             response: *const u8, response_len: c_int) -> sgx_status_t {
    let session_key: sgx_key_128bit_t = src_session_key_get(&dest_enclave_id); // Session Key
    let ciphertext = unsafe{slice::from_raw_parts(response, response_len as usize)};
    println!("ciphertext: {:?}", ciphertext);
    let s = String::from_utf8(ciphertext.to_vec()).unwrap();
    let node_key = deconstruct_payload(&s, &session_key);
    println!("decrypted: {:?}", node_key);
    sgx_status_t::SGX_SUCCESS
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
pub struct Transaction {
    pub oldhash: u32,   
    pub tx_str: [u8; 2048],
    pub newhash: u32,
    pub report: sgx_report_t,
    pub remote_attn_response: [u8; 2048],
} 

/// Define struct MessageInC.
#[repr(C)]
pub struct MessageInC {
    pub func: [u8; 2048],
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

/// create local attestation data: SHA256(oldhash;tx;newhash)
pub fn create_attn_data(oldhash: u32, tx: &str, newhash: u32) -> sgx_report_data_t {
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();

    println!("[Exec]Creating attestation data:");

    // construct SHA256(oldhash;tx;newhash)
    let temp = format!("{};{};{}", oldhash, tx, newhash);
    println!("[Exec]{:?}", temp);
    let result = rsgx_sha256_slice(temp.as_bytes());
    match result {
        Ok(hash) => {
                        println!("SHA256: {:02X}", hash.iter().format("")); 
                        report_data.d[..32].clone_from_slice(&hash);
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
             wasmargs_ptr: *mut i32, wasmargs_len: c_int) -> (String, i32, i32) {
    // Step 1: construct wasmfunc/wasmargs
    let wasmfunc_bytes = unsafe{slice::from_raw_parts(wasmfunc_ptr, wasmfunc_len as usize)};
    let wasmfunc_str = String::from_utf8(wasmfunc_bytes.to_vec()).unwrap();

    let wasmargs_bytes = unsafe{slice::from_raw_parts(wasmargs_ptr, (wasmargs_len/4) as usize)};
    let wasmargs_vec: Vec<i32> = wasmargs_bytes.to_vec();

    // Step 2: get node ID of code&data node
    let codeid = MTGetLeafId(codeproof) as i32;
    let dataid = MTGetLeafId(dataproof) as i32;

    // Step 3: construct Tx
    let tx = format!("TX: codeid: {}, dataid: {}, wasm_func: {}, wasmargs: {:?}", 
                    codeid, dataid, wasmfunc_str, wasmargs_vec);
    println!("[Exec] {}", tx);
    (tx, codeid, dataid)

}

fn create_transaction(oldhash: &u32, tx_str_in: &str, newhash: &u32, new_report: &sgx_report_t, tx_out: &mut Transaction) {
    unsafe{ptr::copy_nonoverlapping(oldhash as *const u32, &mut tx_out.oldhash as *mut u32, 1)};
    unsafe{ptr::copy_nonoverlapping(tx_str_in.as_ptr(), tx_out.tx_str.as_mut_ptr(), tx_str_in.len())};
    unsafe{ptr::copy_nonoverlapping(newhash as *const u32, &mut tx_out.newhash as *mut u32, 1)};
    unsafe{ptr::copy_nonoverlapping(new_report as *const sgx_report_t, 
                                    &mut tx_out.report as *mut sgx_report_t, 1);}    
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


/// Deal with Message Array from wasmi, and copy it to msg_array in App.cpp.
fn assign_msg_array(msg_array: &mut [MessageInC; 100], wasmi_msg_arr: &Vec<Message>) -> String {
    let mut index: usize = 0;
    let mut msg_string = format!("{}", "Msg:");
    for msg in wasmi_msg_arr {
        if index >= 100 {
            println!("messages are more than 100");
            break;
        }

        // func name
        let mut temp_func = [0; 2048];
        temp_func[..msg.function.len()].clone_from_slice(&msg.function.as_bytes());

        // func parameters
        let mut temp_params = [0; 100];
        temp_params[..msg.args.len()].clone_from_slice(&msg.args[..]);

        // others
        let temp_others:[i32; 4] = [msg.func_len, msg.args_len, msg.codeid, msg.dataid];
        
        let temp_msg = MessageInC{func: temp_func, params: temp_params, others: temp_others};
        msg_array[index] = temp_msg.clone();
        index = index + 1;

        // construct msg_string
        msg_string = format!("{} idx:{}, func:{}, params:{:?}, others:{:?};", 
                            msg_string, index, &msg.function, &msg.args[..], &temp_others);
    }
    msg_string
 
}

/// ecall function, the main entry of the execution enclave
#[no_mangle]
pub extern "C" fn ecall_merkle_tree_entry(codeproof: *mut MerkleProof, dataproof: *mut MerkleProof, oldhash: u32, 
                                wasmfunc_ptr: *mut u8, wasmfunc_len: c_int, wasmargs_ptr: *mut i32, wasmargs_len: c_int,
                                data_out: *mut u8, tx_out: &mut Transaction, ti: &sgx_target_info_t,
                                msg_array: &mut [MessageInC; 100], msg_count: *mut c_int, msg_size: c_int) -> sgx_status_t { 

    // Step 1: check MerkleProof of code/data
    if !MTCheckMerkleProof(codeproof) || !MTCheckMerkleProof(dataproof)
    {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    // Step 2: create transaction (for step 7)
    // and get codeid, dataid
    let (tx_str, codeid, dataid) = create_tx(codeproof, dataproof, wasmfunc_ptr, wasmfunc_len, wasmargs_ptr, wasmargs_len);
    println!("Inside ecall_merkle_tree_entry(): {}", tx_str);
    println!("codeid is {:?} dataid is {:?}", codeid, dataid);


    // Step 3: get the value of the code/data nodes (leaf node)
    let code_val = MTGetLeafValue(codeproof);
    println!("Inside ecall_merkle_tree_entry(): code_val: {} len: {} ", 
            code_val, code_val.len());

    let data_val = MTGetLeafValue(dataproof);
    println!("Inside ecall_merkle_tree_entry(): data_val: {} len: {} ", 
            data_val, data_val.len());

    // Step 4: decode & decrypt (code/data nodes)
    let node_key = sgx_key_128bit_t::default();
    let mut code_decrypted = deconstruct_payload(&code_val.as_str(), &node_key);
    let mut data_decrypted = deconstruct_payload(&data_val.as_str(), &node_key);

    // Step 5.1: pass code/data to wasmi and run
    let wasmfunc_bytes = unsafe{slice::from_raw_parts(wasmfunc_ptr, wasmfunc_len as usize)};
    let wasmfunc_str = String::from_utf8(wasmfunc_bytes.to_vec()).unwrap();

    let wasmargs_bytes = unsafe{slice::from_raw_parts(wasmargs_ptr, (wasmargs_len/4) as usize)};
    let wasmargs_vec: Vec<i32> = wasmargs_bytes.to_vec();
    println!("\n\nInside ecall_merkle_tree_entry(): oldhash {}, wasmfunc: {:?}, wasmargs: {:?}", 
            oldhash, wasmfunc_str, wasmargs_vec);

    // Step 5.2: run the module and pass the result MessageArray to app
    let messageArray = wasmi_plugin::run_func(&mut code_decrypted, &mut data_decrypted, &wasmfunc_str, wasmargs_vec.clone(), codeid, dataid);
    println!("\n\nInside ecall_merkle_tree_entry(): new memory is {:?}", data_decrypted);
    let temp_len = messageArray.len() as i32;
    unsafe{ptr::copy_nonoverlapping(&temp_len as *const c_int, msg_count as *mut c_int, 1)};
    let msg_string = assign_msg_array(msg_array, &messageArray);

    // Step 6: generate new ROOT inside the enclave
    let new_data = construct_payload(&data_decrypted, &node_key);
    let mut newhash = MTGenNewRootHash(dataproof, &new_data.as_bytes().to_vec());
    println!("Inside ecall_merkle_tree_entry(): new ROOT hash: {:?}", newhash);

    // Step 7.1: append messageArray to tx_str
    let tx_str_with_msg = format!("{};MsgArray:{}", tx_str, msg_string);

    // Step 7.2: create attestation data([..32]: SHA256(oldhash;tx;newhash))
    let attn_data = create_attn_data(oldhash, &tx_str_with_msg, newhash);

    // Step 8: generate attn report
    let new_report = gen_local_report_rust(&ti, &attn_data);

    // Step 9: prepare outputs

    // Step 9.1: prepare data_out
    println!("Inside ecall_merkle_tree_entry(): data_out: {}", new_data);
    unsafe{ptr::copy_nonoverlapping(new_data.as_ptr(), data_out, new_data.len())};

    // Step 9.2: prepare Transaction
    create_transaction(&oldhash, &tx_str_with_msg, &newhash, &new_report, tx_out);

    sgx_status_t::SGX_SUCCESS

}
