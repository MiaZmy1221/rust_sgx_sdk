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

#![crate_name = "attestation"]
#![crate_type = "rlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(improper_ctypes)]
#![allow(non_camel_case_types)]

#[macro_use]
extern crate sgx_types;
extern crate sgx_tdh;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_trts;

pub mod err;
pub use self::err::*;

pub mod types;
pub use self::types::*;

use sgx_types::*;
use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use sgx_tdh::{SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhInitiator, SgxDhResponder};
use std::boxed::Box;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::mem;

#[macro_use]
extern crate lazy_static;
use std::collections::HashMap;
use std::ptr;
use std::sync::SgxMutex;

lazy_static!{
    static ref DEST_SESSION_KEY_MAP: SgxMutex<HashMap<sgx_enclave_id_t, sgx_key_128bit_t>> // stores the source enclave id
    = SgxMutex::new(HashMap::new());
}

pub fn dest_session_key_insert(id: &sgx_enclave_id_t, session_key: &sgx_key_128bit_t) {
    DEST_SESSION_KEY_MAP.lock().unwrap().insert( id.clone(), session_key.clone());
}

pub fn dest_session_key_print() {
    let v = DEST_SESSION_KEY_MAP.lock().unwrap();
    for (&key, &val) in v.iter() {
        println!("DEST MAP: {:?} - {:?}", key, val);        
    }
}

pub fn dest_session_key_get(id: &sgx_enclave_id_t) -> sgx_key_128bit_t {
    DEST_SESSION_KEY_MAP.lock().unwrap().get(id).unwrap().clone()
}

pub fn dest_session_key_remove(id: &sgx_enclave_id_t) {
    DEST_SESSION_KEY_MAP.lock().unwrap().remove(id);
}

lazy_static!{
    static ref SRC_SESSION_KEY_MAP: SgxMutex<HashMap<sgx_enclave_id_t, sgx_key_128bit_t>> // stores the dest enclave id
    = SgxMutex::new(HashMap::new());
}

pub fn src_session_key_insert(id: &sgx_enclave_id_t, session_key: &sgx_key_128bit_t) {
    SRC_SESSION_KEY_MAP.lock().unwrap().insert( id.clone(), session_key.clone());
}

pub fn src_session_key_print() {
    let v = SRC_SESSION_KEY_MAP.lock().unwrap();
    for (&key, &val) in v.iter() {
        println!("SRC MAP: {:?} - {:?}", key, val);        
    }

}

pub fn src_session_key_get(id: &sgx_enclave_id_t) -> sgx_key_128bit_t {
    SRC_SESSION_KEY_MAP.lock().unwrap().get(id).unwrap().clone()
}

pub fn src_session_key_remove(id: &sgx_enclave_id_t) {
    SRC_SESSION_KEY_MAP.lock().unwrap().remove(id);
}

extern {
    pub fn session_request_ocall(ret: *mut u32,
                                 src_enclave_id: sgx_enclave_id_t,
                                 dest_enclave_id: sgx_enclave_id_t,
                                 dh_msg1: *mut sgx_dh_msg1_t) -> sgx_status_t;

    pub fn exchange_report_ocall(ret: *mut u32,
                                 src_enclave_id: sgx_enclave_id_t,
                                 dest_enclave_id: sgx_enclave_id_t,
                                 dh_msg2: *mut sgx_dh_msg2_t,
                                 dh_msg3: *mut sgx_dh_msg3_t) -> sgx_status_t;

    pub fn end_session_ocall(ret: *mut u32,
                             src_enclave_id:sgx_enclave_id_t,
                             dest_enclave_id:sgx_enclave_id_t) -> sgx_status_t;
}

static CALLBACK_FN: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());

pub fn init(cb: Callback) {
    let ptr = CALLBACK_FN.load(Ordering::SeqCst);
    if ptr.is_null() {
        let ptr: * mut Callback = Box::into_raw(Box::new(cb));
        CALLBACK_FN.store(ptr as * mut (), Ordering::SeqCst);
    }
}

fn get_callback() -> Option<&'static Callback>{
    let ptr = CALLBACK_FN.load(Ordering::SeqCst) as *mut Callback;
    if ptr.is_null() {
         return None;
    }
    unsafe { Some( &* ptr ) }
}

pub fn create_session(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t, session_key: &mut sgx_key_128bit_t) 
    -> ATTESTATION_STATUS {

    let mut dh_msg1: SgxDhMsg1 = SgxDhMsg1::default(); //Diffie-Hellman Message 1
    let mut dh_msg2: SgxDhMsg2 = SgxDhMsg2::default(); //Diffie-Hellman Message 2
    let mut dh_aek: sgx_key_128bit_t = sgx_key_128bit_t::default(); // Session Key
    let mut responder_identity: sgx_dh_session_enclave_identity_t = sgx_dh_session_enclave_identity_t::default();
    let mut ret = 0;

    let mut initiator: SgxDhInitiator = SgxDhInitiator::init_session();

    let status = unsafe { session_request_ocall(&mut ret, src_enclave_id, dest_enclave_id, &mut dh_msg1) };
    if status != sgx_status_t::SGX_SUCCESS {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    let err = ATTESTATION_STATUS::from_repr(ret).unwrap();
    if err != ATTESTATION_STATUS::SUCCESS{
        return err;
    }

    let status = initiator.proc_msg1(&dh_msg1, &mut dh_msg2);
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    let mut dh_msg3_raw = sgx_dh_msg3_t::default();
    let status = unsafe { exchange_report_ocall(&mut ret, src_enclave_id, dest_enclave_id, &mut dh_msg2, &mut dh_msg3_raw as *mut sgx_dh_msg3_t) };
    if status != sgx_status_t::SGX_SUCCESS {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    if ret != ATTESTATION_STATUS::SUCCESS as u32 {
        return ATTESTATION_STATUS::from_repr(ret).unwrap();
    }

    let dh_msg3_raw_len = mem::size_of::<sgx_dh_msg3_t>() as u32 + dh_msg3_raw.msg3_body.additional_prop_length;
    let dh_msg3 = unsafe{ SgxDhMsg3::from_raw_dh_msg3_t(&mut dh_msg3_raw, dh_msg3_raw_len ) };
    if dh_msg3.is_none() {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    let dh_msg3 = dh_msg3.unwrap();

    let status = initiator.proc_msg3(&dh_msg3, &mut dh_aek, &mut responder_identity);
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    let cb = get_callback();
    if cb.is_some() {
        let ret = (cb.unwrap().verify)(&responder_identity);
        if ret != ATTESTATION_STATUS::SUCCESS as u32{
            return ATTESTATION_STATUS::INVALID_SESSION;
        }
    }

    // copy session key to the source enclave
    unsafe{
    ptr::copy_nonoverlapping(&dh_aek as *const sgx_key_128bit_t, 
                             session_key as *mut sgx_key_128bit_t,
                            1);
    }

    ATTESTATION_STATUS::SUCCESS
}

pub fn close_session(src_enclave_id: sgx_enclave_id_t, dest_enclave_id: sgx_enclave_id_t) -> ATTESTATION_STATUS {
    let mut ret = 0;
    let status = unsafe { end_session_ocall(&mut ret, src_enclave_id, dest_enclave_id) };
    if status != sgx_status_t::SGX_SUCCESS {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    ATTESTATION_STATUS::from_repr(ret as u32).unwrap()
}

fn session_request_safe(src_enclave_id: sgx_enclave_id_t, dh_msg1: &mut sgx_dh_msg1_t, session_ptr: &mut usize) -> ATTESTATION_STATUS {

    let mut responder = SgxDhResponder::init_session();

    let status = responder.gen_msg1(dh_msg1);
    if status.is_err() {
        return ATTESTATION_STATUS::INVALID_SESSION;
    }

    let mut session_info = DhSessionInfo::default();
    session_info.enclave_id = src_enclave_id;
    session_info.session.session_status = DhSessionStatus::InProgress(responder);

    let ptr = Box::into_raw(Box::new(session_info));
    *session_ptr = ptr as * mut _ as usize;

    ATTESTATION_STATUS::SUCCESS
}

//Handle the request from Source Enclave for a session
#[no_mangle]
pub extern "C" fn session_request(src_enclave_id: sgx_enclave_id_t, dh_msg1: *mut sgx_dh_msg1_t, session_ptr: *mut usize) -> ATTESTATION_STATUS {
    unsafe {
        session_request_safe(src_enclave_id, &mut *dh_msg1, &mut *session_ptr)
    }
}

#[allow(unused_variables)]
fn exchange_report_safe(src_enclave_id: sgx_enclave_id_t, dh_msg2: &mut sgx_dh_msg2_t , dh_msg3: &mut sgx_dh_msg3_t, session_info: &mut DhSessionInfo) -> ATTESTATION_STATUS {

    let mut dh_aek = sgx_key_128bit_t::default() ;   // Session key
    let mut initiator_identity = sgx_dh_session_enclave_identity_t::default();

    let mut responder = match session_info.session.session_status {
        DhSessionStatus::InProgress(res) => {res},
        _ => {
            return ATTESTATION_STATUS::INVALID_SESSION;
        }
    };

    let mut dh_msg3_r = SgxDhMsg3::default();
    let status = responder.proc_msg2(dh_msg2, &mut dh_msg3_r, &mut dh_aek, &mut initiator_identity);
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    unsafe{ dh_msg3_r.to_raw_dh_msg3_t(dh_msg3, (dh_msg3.msg3_body.additional_prop_length as usize + mem::size_of::<sgx_dh_msg3_t>() ) as u32); };

    let cb = get_callback();
    if cb.is_some() {
        let ret = (cb.unwrap().verify)(&initiator_identity);
        if ret != ATTESTATION_STATUS::SUCCESS as u32 {
            return ATTESTATION_STATUS::INVALID_SESSION;
        }
    }

    session_info.session.session_status = DhSessionStatus::Active(dh_aek);

    // store session key
    // println!("after exchange_report_safe: {:?} session_info: {:?}", dh_aek, session_info.enclave_id);
    dest_session_key_insert(&src_enclave_id, &dh_aek);
    dest_session_key_print();

    ATTESTATION_STATUS::SUCCESS
}
//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
#[no_mangle]
pub extern "C" fn exchange_report(src_enclave_id: sgx_enclave_id_t, dh_msg2: *mut sgx_dh_msg2_t , dh_msg3: *mut sgx_dh_msg3_t, session_ptr: *mut usize) -> ATTESTATION_STATUS {

    if rsgx_raw_is_outside_enclave(session_ptr as * const u8, mem::size_of::<DhSessionInfo>()) {
        return ATTESTATION_STATUS::INVALID_PARAMETER;
    }
    rsgx_lfence();

    unsafe {
        exchange_report_safe(src_enclave_id, &mut *dh_msg2, &mut *dh_msg3, &mut *(session_ptr as *mut DhSessionInfo))
    }
}

//Respond to the request from the Source Enclave to close the session
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn end_session(src_enclave_id: sgx_enclave_id_t, session_ptr: *mut usize) -> ATTESTATION_STATUS {

    if rsgx_raw_is_outside_enclave(session_ptr as * const u8, mem::size_of::<DhSessionInfo>()) {
        return ATTESTATION_STATUS::INVALID_PARAMETER;
    }
    rsgx_lfence();

    let _ = unsafe { Box::from_raw(session_ptr as *mut DhSessionInfo) };

    dest_session_key_remove(&src_enclave_id);
    ATTESTATION_STATUS::SUCCESS
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// DHKE related

mod hex;
use std::string::String;
use std::vec::Vec;
extern crate sgx_tcrypto;
use sgx_tcrypto::*;

/// encrypt & encode
pub fn construct_payload(plaintext: &Vec<u8>, key: &[u8; 16]) -> String {
    let mut ciphertext: Vec<u8> = vec![0; plaintext.len()];

    let mut payload: Vec<u8> = vec![0; 0]; // iv + mac + ciphertext 

    // let key : [u8; 16] = [0; 16];
    let iv : [u8; 12] = [0; 12];
    let mut mac : [u8; 16] = [0; 16];

    aes_gcm_128_encrypt(key,
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
pub fn deconstruct_payload(payload: &str, key: &[u8; 16]) -> Vec<u8> {
    let decoded = hex::decode_hex_no_space(&payload);
    
    // let key: [u8; 16] = [0; 16];
    let mut iv2: [u8; 12] = [0; 12];
    let mut mac2: [u8; 16] = [0; 16];
    let mut ciphertext2 = vec![0; decoded.len()-12-16];
    let mut decrypted: Vec<u8> = vec![0; decoded.len()-12-16];

    iv2.clone_from_slice(&decoded[..12]);
    mac2.clone_from_slice(&decoded[12..28]);
    ciphertext2.clone_from_slice(&decoded[28..]);

    aes_gcm_128_decrypt(key,
                        &ciphertext2,
                        &iv2,
                        &mac2,
                        &mut decrypted);
    decrypted
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
