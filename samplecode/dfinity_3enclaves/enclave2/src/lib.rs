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

#![crate_name = "enclave2"]  // validation enclave
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_trts;
extern crate sgx_tse;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate sgx_types;
extern crate sgx_tcrypto;
use sgx_types::*;
use sgx_tse::*;
use sgx_tcrypto::*;

extern crate untrusted;

extern crate attestation;

extern crate rustls;
extern crate webpki;
extern crate itertools;
extern crate base64;
extern crate httparse;
extern crate yasna;
extern crate bit_vec;
extern crate num_bigint;
extern crate serde_json;
extern crate chrono;
extern crate webpki_roots;


use attestation::types::*;
use attestation::err::*;
use attestation::func::*;

use sgx_rand::*;
use std::ptr;
use std::string::String;
use std::io::{Write, Read, BufReader};
use std::untrusted::fs;
use std::vec::Vec;
use itertools::Itertools;
use std::prelude::v1::*;
use std::sync::Arc;
use std::net::TcpStream;
use std::str;
use std::slice;


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
#[repr(C)]
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
} 

}


/// get the node ID of the leaf node from MerkleProof
pub fn MTGetLeafId(mp: *mut MerkleProof) -> c_int {
    let ref_mut: &mut MerkleProof = unsafe{&mut *mp};
    let leaf = &mut ref_mut.path[0];
    leaf.prefix
}

// remove trailing `0`s in String
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



mod hex;

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

/// create local attestation data: SHA256(oldroot;tx;newroot)
pub fn create_attn_data(oldhash: u32, tx: &str, newhash: u32) -> sgx_report_data_t {
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();

    println!("[Validation]Creating attestation data:");

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

/// verify the attestation data by regenerating it inside Validation Enclave
fn verify_tx(tx_array: &[Transaction], tx_count: c_int) -> bool {
    for idx in 1..tx_count as usize {
        let old_tx = &tx_array[idx-1];
        let new_tx = &tx_array[idx];
        if old_tx.newhash != new_tx.oldhash
        {
            // transaction is not authentic
            println!("[Validation]Something is wrong with the transaction {} and {}!", idx-1, idx);
            return false;
        }
    }
    println!("[Validation]Transaction order is verified!");
    true
}

fn verify_report(tx_array: &[Transaction], exec_ti: &sgx_target_info_t) -> bool {

    for tx in tx_array.iter() {
        let report = &tx.report;
        // verify measurement 
        if (exec_ti.mr_enclave.m != report.body.mr_enclave.m)
        {
            println!("[Validation]Report is created by unknown enclave!");
            return false;
        }
        // verify report
        let rep = match rsgx_verify_report(report) {
            Ok(r) =>{
                Some(r)
            },
            Err(e) =>{
                println!("[Validation]Report verification failed {:?}", e);
                return false
            },
        };
    }
    
    println!("[Validation]Report is created by the Exec Enclave!");
    println!("[Validation]Report verified!");
    true
}

/// read and verify the report generated by the Execution Enclave
#[no_mangle]
pub extern "C" fn ecall_read_and_verify_report( tx_array: &[Transaction; 100], tx_count: c_int, tx_size: c_int, 
                                                exec_ti: &sgx_target_info_t) 
                                                -> sgx_status_t {
    

    // verify report
    if !verify_report(&tx_array[..tx_count as usize], exec_ti)
    {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }

    // verify tx
    if !verify_tx(&tx_array[..tx_count as usize], tx_count)
    {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }

    // when to request remote attn? what to put in report_data?
    {
        // call attn
        // println!("[Validation]Starting remote attestation:");
        // let attn_report = remote_attn(&report.body.report_data.d.clone());
        // println!("[Validation]Remote Attestation Report: {}", attn_report);
    }
    sgx_status_t::SGX_SUCCESS
}

// remote attestation
#[no_mangle]
pub extern "C" fn remote_attn(data: &[u8; SGX_REPORT_DATA_SIZE]) -> String {

    // Generate Keypair
    // let ecc_handle = SgxEccHandle::new();
    // ecc_handle.open().unwrap();
    // let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    report_data.d[..].clone_from_slice(&data[..]);

    let (attn_report, sig, cert) = match create_attestation_report(&report_data) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return String::from("ERROR");
        }
    };

    // ecc_handle.close().unwrap();

    println!("remote attestation finished");

    attn_report
}



// Attestation code from Rust-SDK

extern "C" {
    pub fn ocall_sgx_init_quote ( ret_val : *mut sgx_status_t,
                  ret_ti  : *mut sgx_target_info_t,
                  ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t;
    pub fn ocall_get_ias_socket ( ret_val : *mut sgx_status_t,
                  ret_fd  : *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote (ret_val            : *mut sgx_status_t,
                p_sigrl            : *const u8,
                sigrl_len          : u32,
                p_report           : *const sgx_report_t,
                quote_type         : sgx_quote_sign_type_t,
                p_spid             : *const sgx_spid_t,
                p_nonce            : *const sgx_quote_nonce_t,
                p_qe_report        : *mut sgx_report_t,
                p_quote            : *mut u8,
                maxlen             : u32,
                p_quote_len        : *mut u32) -> sgx_status_t;
}


mod cert;

pub const DEV_HOSTNAME:&'static str = "test-as.sgx.trustedservices.intel.com";
//pub const PROD_HOSTNAME:&'static str = "as.sgx.trustedservices.intel.com";
pub const SIGRL_SUFFIX:&'static str = "/attestation/sgx/v3/sigrl/";
pub const REPORT_SUFFIX:&'static str = "/attestation/sgx/v3/report";

fn parse_response_attn_report(resp : &[u8]) -> (String, String, String){
    println!("parse_response_attn_report");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => {println!("DBG:{}", respp.code.unwrap()); msg = "Unknown error occured"},
    }

    println!("{}", msg);
    let mut len_num : u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name{
            "content-length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
            "x-iasreport-signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "x-iasreport-signing-certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        // println!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}


fn parse_response_sigrl(resp : &[u8]) -> Vec<u8> {
    println!("parse_response_sigrl");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp   = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    println!("parse result {:?}", result);
    // println!("parse response{:?}", respp);

    let msg : &'static str;

    match respp.code {
        Some(200) => msg = "OK Operation Successful",
        Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
        Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
        Some(500) => msg = "Internal error occurred",
        Some(503) => msg = "Service is currently not able to process the request (due to
            a temporary overloading or maintenance). This is a
            temporary state – the same request can be repeated after
            some time. ",
        _ => msg = "Unknown error occured",
    }

    println!("{}", msg);
    let mut len_num : u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        println!("Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let certs = load_certs("client.crt");
    let privkey = load_private_key("client.key");
    config.set_single_client_cert(certs, privkey);

    config
}


pub fn get_sigrl_from_intel(fd : c_int, gid : u32) -> Vec<u8> {
    println!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    //let sigrl_arg = SigRLArg { group_id : gid };
    //let sigrl_req = sigrl_arg.to_httpreq();

    let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\n\r\n",
                        SIGRL_SUFFIX,
                        gid,
                        SIGRL_SUFFIX);
    println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!("haha");
        }
    }
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();

    println!("{}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd : c_int, quote : Vec<u8>) -> (String, String, String) {
    println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nContent-Length:{}\r\nContent-Type: application/json\r\n\r\n{}",
                           REPORT_SUFFIX,
                           DEV_HOSTNAME,
                           encoded_json.len(),
                           encoded_json);
    // println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    println!("read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).unwrap();
    // println!("resp_string = {}", resp_string);

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
    ((array[1] as u32) <<  8) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}

#[allow(const_err)] // pub_k: &sgx_ec256_public_t, 
pub fn create_attestation_report(report_data: &sgx_report_data_t) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();
    let mut eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe{ocall_sgx_init_quote(&mut rt as *mut sgx_status_t,
                             &mut ti as *mut sgx_target_info_t,
                             &mut eg as *mut sgx_epid_group_id_t)
    };

    println!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock : i32 = 0;

    let res = unsafe {
        ocall_get_ias_socket(&mut rt as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    //println!("Got ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec : Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num);

    // (2) Generate the report
    // // Fill ecc256 public key into report_data
    // let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    // let mut pub_k_gx = pub_k.gx.clone();
    // pub_k_gx.reverse();
    // let mut pub_k_gy = pub_k.gy.clone();
    // pub_k_gy.reverse();
    // report_data.d[..32].clone_from_slice(&pub_k_gx);
    // report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            println!("[Validation]Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        },
        Err(e) =>{
            println!("[Validation]Report creation => failed {:?}", e);
            None
        },
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    // println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN : u32 = 2048;
    let mut return_quote_buf : [u8; RET_QUOTE_BUF_LEN as usize] = [0;RET_QUOTE_BUF_LEN as usize];
    let mut quote_len : u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) =
        if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
        };
    let p_report = (&rep.unwrap()) as * const sgx_report_t;
    let quote_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

    let spid : sgx_spid_t = load_spid("spid.txt");

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as * const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(&mut rt as *mut sgx_status_t,
                p_sigrl,
                sigrl_len,
                p_report,
                quote_type,
                p_spid,
                p_nonce,
                p_qe_report,
                p_quote,
                maxlen,
                p_quote_len)
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => println!("rsgx_verify_report passed!"),
        Err(x) => {
            println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        },
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m ||
       ti.attributes.flags != qe_report.body.attributes.flags ||
       ti.attributes.xfrm  != qe_report.body.attributes.xfrm {
        println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    println!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec : Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        println!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec : Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res = unsafe {
        ocall_get_ias_socket(&mut rt as *mut sgx_status_t,
                             &mut ias_sock as *mut i32)
    };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec);
    Ok((attn_report, sig, cert))
}

fn load_spid(filename: &str) -> sgx_spid_t {
    let mut spidfile = fs::File::open(filename).expect("cannot open spid file");
    let mut contents = String::new();
    spidfile.read_to_string(&mut contents).expect("cannot read the spid file");

    hex::decode_spid(&contents)
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    match rustls::internal::pemfile::certs(&mut reader) {
        Ok(r) => return r,
        Err(e) => {
            println!("Err in load_certs: {:?}", e);
            panic!("");
        }
    }
}
fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
    let keyfile = fs::File::open(filename)
        .expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    rustls::internal::pemfile::rsa_private_keys(&mut reader)
        .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
    let keyfile = fs::File::open(filename)
        .expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
        .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

