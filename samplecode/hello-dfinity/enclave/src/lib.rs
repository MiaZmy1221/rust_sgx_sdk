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

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

extern crate untrusted;
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


use std::backtrace::{self, PrintFormat};
use sgx_types::*;
use sgx_tse::*;
//use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence};
use sgx_tcrypto::*;
use sgx_rand::*;

use std::prelude::v1::*;
use std::sync::Arc;
use std::net::TcpStream;
use std::string::String;
use std::io;
use std::ptr;
use std::str;
use std::io::{Write, Read, BufReader};
use std::untrusted::fs;
use std::vec::Vec;
use itertools::Itertools;
use std::ffi::CStr;
use std::boxed::Box;


// wasmi
#[macro_use]
extern crate lazy_static;
extern crate wasmi;
extern crate sgxwasm;
extern crate serde;

use std::slice;
use std::mem;

use std::sync::SgxMutex;

use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};

use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module, NopExternals};


// MerkleTree
const MAX_LEAF_NODE: i32 = 64;
const MAX_LEN: i32 = 256;
const MAX_TREE_LEVEL: i32 = 7;
s! {
#[repr(C)]
pub struct Node
{
    pub hash: c_int,
    pub lefthash: c_int,
    pub righthash: c_int,
    pub prefix: c_int,
    pub value: [u8; 256],



}
#[repr(C)]
pub struct MerkleTree
{

   pub nodes: [Node; 128],
   pub totalLeafNode: c_int, 

}


#[repr(C)]
pub struct LinkedNode 
{

   pub parent: *mut LinkedNode,
   pub treeIdx: c_int,
   pub node: Node,
}

pub struct MerkleProof 
{

   pub path: [Node; 7],

}

}


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

extern "C"{  
    pub fn MTUpdateNode(tree: *mut MerkleTree, idx: c_int);
    pub fn MTGetMerkleProof(tree: *mut MerkleTree, nodeidx: c_int, pointer: *mut Box<MerkleProof>);
}

pub fn MTSerializeNodeByPtr(pointer: *mut Node) -> c_int 
{
    let mut s = String::new();
    let mut valuestr =  String::new();
    for i in 0..256
    {
        valuestr.push(unsafe{(*pointer)}.value[i] as char);
    }
    format!("L{}R{}P{}V{}", unsafe{(*pointer)}.lefthash, unsafe{(*pointer)}.righthash, unsafe{(*pointer)}.prefix, valuestr);    
    let len: usize = s.len();
    let mut hash = 5381;
        for c in 0..len
        {
            hash = hash * 33 + s.chars().next().unwrap() as c_int;
        }
        
    return hash;

}


pub fn MTGenNodeHashByPtr(pointer: *mut Node)
{
    unsafe{(*pointer)}.hash = MTSerializeNodeByPtr(pointer);
    return;
}


pub fn MTCheckNodeHashByPtr(pointer: *mut Node) -> bool
{
        let mut old = unsafe{(*pointer)}.hash;
        MTGenNodeHashByPtr(pointer);
        if (old != unsafe{(*pointer)}.hash)
        {
                println!("{} old hash: {}, new hash: {}\n",
                        "ERROR checking node:", old, unsafe{(*pointer)}.hash);
                return false;
        }
        return true;
}

pub fn MTCheckMerkleProof(mp: *mut Box<MerkleProof>) -> bool
{
    let ref_mut: &mut Box<MerkleProof> = unsafe{&mut *mp};
        for i in 0..MAX_TREE_LEVEL{
                if (!MTCheckNodeHashByPtr(&mut ref_mut.path[i as usize] as *mut Node)) 
                {
                        println!("{}\n", "MTCheckMerkleProof failed");
                        return false;
                }}
        println!("{}\n", "MTCheckMerkleProof passed");
        return true;
}
#[no_mangle]
pub extern "C" fn merkletreeflow(tree: * mut Box<MerkleTree>, roothash: c_int, codeid: c_int, dataid: c_int, 
    report: &mut str, wasmfunc: &str, wasmargs: c_int) -> sgx_status_t { 

    println!(" codeid {}", codeid);
    println!(" dataid {}", dataid);
    println!(" roothash {}", roothash);
    println!(" wasmargs {}", wasmargs);
    let leafidx = 4;
    let idx = leafidx+MAX_LEAF_NODE; 
    let mut result: Box<MerkleProof> = Box::new(MerkleProof{
        path: unsafe{mem::zeroed()}});

    
    unsafe{
        MTGetMerkleProof(tree as *mut MerkleTree, idx, &mut result)};
    
    MTCheckMerkleProof(&mut result as *mut Box<MerkleProof>); 
    
    let mem = dfinity_code_run();
    println!("mem: {}", mem);

    // call attn
    let attn_report = run_report_gen(codeid, dataid, roothash as u32, roothash as u32);
    println!("attn_report: {}", attn_report);

    sgx_status_t::SGX_SUCCESS

}



// Attestation

mod cert;
mod hex;

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
        println!("Attestation report: {}", attn_report);
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
    println!("parse response{:?}", respp);

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
    println!("{}", req);
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

    println!("resp_string = {}", resp_string);

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) +
    ((array[1] as u32) <<  8) +
    ((array[2] as u32) << 16) +
    ((array[3] as u32) << 24)
}

fn create_attestation_data(mut data: [u8; SGX_REPORT_DATA_SIZE], codeid: i32, dataid: i32, oldhash: u32, newhash: u32)
{
    println!("\n\n report_data: {:02X} \n\n", data.iter().format(""));

    // construct tx
    let tx = format!("TX: codeid: {}, dataid: {}, oldhash: {}, newhash: {}", codeid, dataid, oldhash, newhash);
    println!("{}", tx);

    // get sha256 of tx
    let result = rsgx_sha256_slice(tx.as_bytes());
    match result {
        Ok(hash) => {println!("Result hash: {:02X}", hash.iter().format("")); data[..32].clone_from_slice(&hash)},
        Err(x) => println!("Error {:?}", x),
    }

    // set second half of data to zero
    let mut second = [0; 32];
    data[32..].clone_from_slice(&second);
    println!("\n\n report_data(after modification): {:02X} \n\n", data.iter().format(""));
}

#[allow(const_err)]
pub fn create_attestation_report(pub_k: &sgx_ec256_public_t, codeid: i32, dataid: i32, oldhash: u32, newhash: u32) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti : sgx_target_info_t = sgx_target_info_t::default();
    let mut eg : sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(&mut rt as *mut sgx_status_t,
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
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    create_attestation_data(report_data.d, codeid, dataid, oldhash, newhash);
    //println!("\n\n report_data: {:02X} \n\n", report_data.d.iter().format(""));

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) =>{
            println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        },
        Err(e) =>{
            println!("Report creation => failed {:?}", e);
            None
        },
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand : [0;16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    println!("rand finished");
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


// new function
#[no_mangle]
pub extern "C" fn run_report_gen(codeid: i32, dataid: i32, oldhash: u32, newhash: u32) -> String {
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    ecc_handle.open().unwrap();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let (attn_report, sig, cert) = match create_attestation_report(&pub_k, codeid, dataid, oldhash, newhash) {
        Ok(r) => r,
        Err(e) => {
            println!("Error in create_attestation_report: {:?}", e);
            return String::from("ERROR");
        }
    };

    ecc_handle.close().unwrap();

    println!("run_report_gen() success");

    attn_report
}



// wasmi

use std::fmt;
//for DfinityFunc
use wasmi::{TableInstance, TableRef, FuncInstance, FuncRef, Signature, ModuleImportResolver, ValueType, Trap, RuntimeArgs, Externals};
use std::collections::HashMap;
//for DfinityData
use wasmi::{MemoryInstance, MemoryRef};
use wasmi::memory_units::Pages;
use std::borrow::BorrowMut;
//Step1: struct
#[derive(Clone)]
pub struct DfinityFunc {
	pub table: Option<TableRef>,
        pub funcmap: HashMap<i32, Vec<u8>>,
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

//Step2: impl struct  //add a new function
impl DfinityFunc {
	fn new() -> DfinityFunc {
		DfinityFunc {
			table: Some(TableInstance::alloc(1, None).unwrap()),
			funcmap: HashMap::new(),
			counter: 0,
		}
	}
}
//Step3: define func index
const FUNC_EXTERNALIZE: usize = 0;
const FUNC_INTERNALIZE: usize = 1;

//Step4: imple Externals
impl Externals for DfinityFunc {
	fn invoke_index(
		&mut self,
		index: usize,
		args: RuntimeArgs,
	) -> Result<Option<RuntimeValue>, Trap> {
		match index {
			FUNC_EXTERNALIZE => {
				println!("THIS IS THE FUNCTION FUN_EXTERNALIZE!");
				let data_counter = self.counter;
				Ok(Some(RuntimeValue::I32(data_counter)))
			}
			FUNC_INTERNALIZE => {
				println!("THIS IS THE FUNCTION FUN_INTERNALIZE!");
				//get the parameters
				let a: u32 = args.nth(0); // slot 
				let b: i32 = args.nth(1); // func ref
				
				//load funcref into table				
				let table = self.table.as_ref().expect(
					"Function 'data_externalize' expects attached memory",
				);
				//b should be the funcref
				//table.set(a, Some(func));

				Ok(None)
			}
			_ => panic!("env doesn't provide function at index {}", index),
		}
	}
}
//Step5: impl function check_signature in the struct DfinityFunc
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
//Step6: impl trait ModuleImportResolver for struct DfinityFunc
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

// add some code

//Step1: struct
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

//Step2: impl struct  add a new function
impl DfinityData {
	fn new() -> DfinityData {
		DfinityData {
			memory: Some(MemoryInstance::alloc(Pages(1), None).unwrap()),
			datamap: HashMap::new(),
			counter: 0,
		}
	}
}
//Step3: define func index
const DATA_EXTERNALIZE: usize = 0;
const DATA_INTERNALIZE: usize = 1;
const DATA_LENGTH: usize = 2;
//Step4: imple Externals
impl Externals for DfinityData {
	fn invoke_index(
		&mut self,
		index: usize,
		args: RuntimeArgs,
	) -> Result<Option<RuntimeValue>, Trap> {
		match index {
			DATA_EXTERNALIZE => {
				let a: u32 = args.nth(0);
				// b must be u8 for function get_into, but for get b must be usize
				let b: i32 = args.nth(1);

				let memory = self.memory.as_ref().expect(
					"Function 'data_externalize' expects attached memory",
				);

				let buf = memory.get(a, b as usize).expect("Successfully retrieve the result");
				
				// insert key:counter, value:buf into 
				let mut data_map = self.datamap.borrow_mut();
				let data_counter = self.counter;
				data_map.insert(data_counter, buf.to_vec());
				self.counter = data_counter + 1;

				let result = Some(RuntimeValue::I32(data_counter));
				println!("result is {:?}, data_map is {:?}", result, data_map);
				

				Ok(result)
			}
			DATA_INTERNALIZE => {
				let a: i32 = args.nth(0); // dst offset  10
				let b: i32 = args.nth(1); // length  buf.length
				let c: i32 = args.nth(2); // databuf  datareference
				let d: i32 = args.nth(3); // src offset 0
				//println!("a is {:?}  b is {:?}  c is {:?}  f is {:?}", a, b, c, d);
				let memory = self.memory.as_ref().expect(
					"Function 'data_externalize' expects attached memory",
				);
				//println!("before internalize, memory is {:?}", memory);
				
				let mut data_map = self.datamap.borrow_mut();
				let buffer = data_map.get(&c);
				//println!("data_internalize function buf is: {:?}", buffer);
				let mem = MemoryInstance::alloc(Pages(1), None).unwrap();
				mem.set(0, &buffer.unwrap()).expect("Successful initialize the memory");
			
				MemoryInstance::transfer(&mem, d as usize, &memory, a as usize, b as usize).unwrap();
				//println!("after internalize, memory is {:?}", memory);			

				Ok(None)
			}
			DATA_LENGTH => {
				let a: i32 = args.nth(0);
				let mut data_map = self.datamap.borrow_mut();
				let buffer = data_map.get(&a);
				//println!("key is {:?}, value is {:?}", a, buffer);
				let length = buffer.unwrap().len();
				//println!("length is {:?}", length);
				let i32length: i32 = length as i32;
		
				Ok(Some(RuntimeValue::I32(i32length)))
			}
			_ => panic!("env doesn't provide function at index {}", index),
		}
	}
}
//Step5: impl function check_signature in the struct DfinityData
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
//Step6: impl trait ModuleImportResolver for struct DfinityData
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

// add new function here
fn run_dfnity_in_lib(code: &mut Vec<u8>, data_str: &str, wasm_func: &str, wasm_args: Vec<i32>) -> String {
    //Step1: add data into this field
    //does not change code, but rather use memory
    //code.extend([0x0b, 0x10, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x0a, 0x48, 0x69, 0x20, 0x44, 0x46, 0x49, 0x4e, 0x49, 0x54, 0x59].iter().cloned());

    // add data to this field
    
    //Step2: instantiate the module
    let module = wasmi::Module::from_buffer(&code).unwrap();
    
    //Step2.1 change module.rs file to the original file in rust sgx sdk's wasmi
    let mut func = DfinityFunc::new();
    let mut data = DfinityData::new();

    let instance = ModuleInstance::new(
        &module,
        &ImportsBuilder::new().with_resolver("data", &data),
    ).expect("Failed to instantiate module")
        .assert_no_start();
    
    //Step1: add data into this field
    let memory = instance.memory_by_index(0).expect("this is the memory of this instance");
    let data_buf = data_str.as_bytes();
    //println!("*****************data is {:?}", data_buf);
    memory.set(0, &data_buf);

    //Step3.0 before invoking the function
    //Get exported memory 
    let internal_mem = instance
		.export_by_name("memory")
		.expect("Module expected to have 'mem' export")
		.as_memory()
		.cloned()
		.expect("'mem' export should be a memory");
    //println!("*************internal memory is {:?}**************", internal_mem);
    data.memory = Some(internal_mem);
    //Step3: invoke the function
    //change wasm_args into args
    println!("*************after invoking function init**************");
    let mut args : Vec<RuntimeValue> = Vec::new();
    for argument in wasm_args {
        let temp_arg = RuntimeValue::I32(argument);
        args.push(temp_arg);
    }
    //Step3.1 change this line of code, invoking function with externlas DfinityData or DfinityFunc
    instance.invoke_export(wasm_func, &mut args, &mut data).expect("");
    println!("*************after invoking function peek***************");
    instance.invoke_export("peek", &[RuntimeValue::I32(0), RuntimeValue::I32(10)], &mut data).expect("");
    
    //Step4: Get the memory 
    //This changes the memory.rs and module.rs
    let memory = instance.memory_by_index(0).unwrap().get_whole_buf().unwrap();
    let memory_str = String::from_utf8(memory).unwrap();    
    memory_str
}
// add new function here
// This function is a ECALL
#[no_mangle]
pub extern "C" fn dfinity_code_run() -> String {
    //add new code here
    //Step0: define 4 parameters of this function 
    let data = "Hi DFINITY";
    //wasm binary is the code
    let mut wasm_binary: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x05, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x00, 0x02, 0x35, 0x03, 0x04, 0x64, 0x61, 0x74, 0x61, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x00, 0x04, 0x64, 0x61, 0x74, 0x61, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x04, 0x64, 0x61, 0x74, 0x61, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x02, 0x03, 0x04, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x7e, 0x0b, 0x07, 0x1e, 0x04, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x04, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x03, 0x03, 0x73, 0x65, 0x74, 0x00, 0x04, 0x04, 0x70, 0x65, 0x65, 0x6b, 0x00, 0x05, 0x0a, 0x2a, 0x03, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x24, 0x00, 0x0b, 0x06, 0x00, 0x20, 0x00, 0x24, 0x00, 0x0b, 0x16, 0x00, 0x41, 0x0a, 0x23, 0x00, 0x10, 0x02, 0x23, 0x00, 0x41, 0x00, 0x10, 0x01, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x24, 0x00, 0x0b].to_vec();
    let wasm_func = "init";
    let mut wasm_args: Vec<i32> = Vec::new();
    wasm_args.push(0 as i32);
    wasm_args.push(10 as i32);
    let memory = run_dfnity_in_lib(&mut wasm_binary, data, wasm_func, wasm_args);
    println!("memory is {:?}", memory);
    memory
}
