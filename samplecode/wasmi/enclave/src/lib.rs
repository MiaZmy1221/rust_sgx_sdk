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

#![crate_name = "wasmienclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

#[macro_use]
extern crate lazy_static;

use std::prelude::v1::*;
use std::sync::SgxMutex;
use std::ptr;

extern crate wasmi;
extern crate sgxwasm;

use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};

use sgx_types::*;
use std::slice;

use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module, NopExternals};

extern crate serde;
extern crate serde_json;

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

// add new code
/*
let code = r#"
	(module
	  ;; (type $t0 (func (param i32 i32))) ;; type of $peek
	  (type $t1 (func (param i32 i32) (result i32))) ;; type of data.externalize
	  (type $t2 (func (param i32 i32 i32 i32))) ;; type of data.internalize
	  (type $t3 (func (param i32) (result i32))) ;; type of data.length
	  (import "data" "externalize" (func $data.ex (type $t1)))
	  (import "data" "internalize" (func $data.in (type $t2)))
	  (import "data" "length" (func $data.len (type $t3)))
	  ;; global storing a databuf reference
	  (global $ref (mut i32) (i32.const -2)) ;; index 0
	  ;; one page (64 KB) of memory
	  (memory (export "memory") 1)
	  ;; initialize memory with a string
	  ;;(data (i32.const 0) "Hi DFINITY")
	  (export "init" (func $init))
	  (export "set" (func $set))
	  (export "peek" (func $peek))
	  (func $init (param $offset i32) (param $len i32)
	    (set_global $ref (call $data.ex (get_local 0) (get_local 1))))
	  (func $set (param $str i32)
	    (set_global $ref (get_local $str)))
	  (func $peek (param $offset i32) (param $len i32)
	    (call $data.in (i32.const 10) (call $data.len (get_global $ref)) (get_global $ref) (i32.const 0))
	    (set_global $ref (call $data.ex (get_local $offset) (get_local $len))))
	)
		"#;

//construct the wast file with data section
	let data_section = format!("(data (i32.const 0) {})", data);
	//println!("data section is {:?}", data_section);
	let mut code_section = code.to_string();
	//println!("code section is {:?}", code_section);
	loop {
		if code_section.pop() == Some(')') {
			break;
		}
	}
	//println!("code section is {:?}", code_section);
	code_section.push_str(&data_section);
	//println!("code section is {:?}", code_section);
	code_section.push(')');
	//println!("code section is {:?}", code_section);

*/

// add new function here
fn run_dfnity_in_lib(code: &mut Vec<u8>, data: &str, wasm_func: &str, wasm_args: Vec<i32>) -> String {
	//Step1: add data into this field
	code.extend([0x0b, 0x10, 0x01, 0x00, 0x41, 0x00, 0x0b, 0x0a, 0x48, 0x69, 0x20, 0x44, 0x46, 0x49, 0x4e, 0x49, 0x54, 0x59].iter().cloned());
	/*let data_buf = data.to_string().into_bytes();
	let data_buf_len = data_buf.len();
	println!("{:?} {:?}", data_buf, data_buf_len);
	let s = String::from_utf8(data_buf).unwrap();
	let data_buf_hex = u8::from_str_radix(&s, 16).unwrap();
	println!("{:?}", data_buf_hex);
	let data_buf = data.as_bytes();
	let data_buf_len = data_buf.len();
	println!("{:?} {:?}", data_buf, data_buf_len);
	
	code.push(0x0b);
	let section_size :u8 = data_buf_len + 6;
	let data_size :u8 = data_buf_len as u8;
	code.push(section_size);
	code.push([]);
	println!("*&*^%^^^^^&$$&${:?}", code);*/

	//Step2: instantiate the module
	let module = wasmi::Module::from_buffer(&code).unwrap();

	let instance = ModuleInstance::new(
		&module,
		&ImportsBuilder::default(),
	).expect("Failed to instantiate module")
		.assert_no_start();
	
	//Step3: invoke the function
	//change wasm_args into args
	println!("*************after invoking function init**************");
	let mut args : Vec<RuntimeValue> = Vec::new();
	for argument in wasm_args {
		let temp_arg = RuntimeValue::I32(argument);
		args.push(temp_arg);
	}
	//args.reverse();
	//println!("&&&&&&&&&&&&&&&&&&args is: {:?}", args);
	instance.invoke_export(wasm_func, &mut args, &mut NopExternals).expect("");
	println!("*************after invoking function peek***************");
	instance.invoke_export("peek", &[RuntimeValue::I32(0), RuntimeValue::I32(10)], &mut NopExternals).expect("");
	

	//Step4: Get the memory	
	//This changes the memory.rs and module.rs
	let memory = instance.memory_by_index(0).unwrap().get_whole_buf().unwrap();
	let memory_str = String::from_utf8(memory).unwrap();	
	memory_str
}

// add new function here
// This function is a ECALL
#[no_mangle]
pub extern "C"
fn dfinity_code_run() -> sgx_status_t {
	//add new code here
	//Step0: define 4 parameters of this function 
        let data = "H";
	let mut wasm_binary: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x1c, 0x05, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x60, 0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x01, 0x7f, 0x00, 0x02, 0x35, 0x03, 0x04, 0x64, 0x61, 0x74, 0x61, 0x0b, 0x65, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x00, 0x04, 0x64, 0x61, 0x74, 0x61, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x04, 0x64, 0x61, 0x74, 0x61, 0x06, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x00, 0x02, 0x03, 0x04, 0x03, 0x03, 0x04, 0x03, 0x05, 0x03, 0x01, 0x00, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x7e, 0x0b, 0x07, 0x1e, 0x04, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00, 0x04, 0x69, 0x6e, 0x69, 0x74, 0x00, 0x03, 0x03, 0x73, 0x65, 0x74, 0x00, 0x04, 0x04, 0x70, 0x65, 0x65, 0x6b, 0x00, 0x05, 0x0a, 0x2a, 0x03, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x24, 0x00, 0x0b, 0x06, 0x00, 0x20, 0x00, 0x24, 0x00, 0x0b, 0x16, 0x00, 0x41, 0x0a, 0x23, 0x00, 0x10, 0x02, 0x23, 0x00, 0x41, 0x00, 0x10, 0x01, 0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x24, 0x00, 0x0b].to_vec();
	let wasm_func = "init";
	let mut wasm_args: Vec<i32> = Vec::new();
	wasm_args.push(0 as i32);
	wasm_args.push(10 as i32);

	let memory = run_dfnity_in_lib(&mut wasm_binary, data, wasm_func, wasm_args);
	println!("memory is {:?}", memory);
	sgx_status_t::SGX_SUCCESS
}


fn wasm_get(module : Option<String>, field : String)
            -> Result<Option<RuntimeValue>, InterpreterError> {
    let program = SPECDRIVER.lock().unwrap();
    let module = match module {
        None => {
                 program
                 .module_or_last(None)
                 .expect(&format!("Expected program to have loaded module {:?}",
                        "None"
                 ))
        },
        Some(str) => {
                 program
                 .module_or_last(Some(&str))
                 .expect(&format!("Expected program to have loaded module {:?}",
                         str
                 ))
        }
    };

    let global = module.export_by_name(&field)
                       .ok_or_else(|| {
                           InterpreterError::Global(format!("Expected to have export with name {}", field))
                       })?
                       .as_global()
                       .cloned()
                       .ok_or_else(|| {
                           InterpreterError::Global(format!("Expected export {} to be a global", field))
                       })?;
     Ok(Some(global.get()))
}

fn try_load_module(wasm: &[u8]) -> Result<Module, InterpreterError> {
    wasmi::Module::from_buffer(wasm).map_err(|e| InterpreterError::Instantiation(format!("Module::from_buffer error {:?}", e)))
}

fn wasm_try_load(wasm: Vec<u8>) -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    let module = try_load_module(&wasm[..])?;
    let instance = ModuleInstance::new(&module, &ImportsBuilder::default())?;
    instance
        .run_start(spec_driver.spec_module())
        .map_err(|trap| InterpreterError::Instantiation(format!("ModuleInstance::run_start error on {:?}", trap)))?;
    Ok(())
}

fn wasm_load_module(name: Option<String>, module: Vec<u8>)
                    -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    let module = try_load_module(&module[..])?;
    let instance = ModuleInstance::new(&module, &**spec_driver)
        .map_err(|e| InterpreterError::Instantiation(format!("ModuleInstance::new error on {:?}", e)))?
        .run_start(spec_driver.spec_module())
        .map_err(|trap| InterpreterError::Instantiation(format!("ModuleInstance::run_start error on {:?}", trap)))?;

    spec_driver.add_module(name, instance.clone());

    Ok(())
}

fn wasm_register(name: &Option<String>, as_name: String)
                    -> Result<(), InterpreterError> {
    let ref mut spec_driver = SPECDRIVER.lock().unwrap();
    spec_driver.register(name, as_name)
}

#[no_mangle]
pub extern "C"
fn sgxwasm_run_action(req_bin : *const u8, req_length: usize,
                      result_bin : *mut u8, result_max_len: usize) -> sgx_status_t {

    let req_slice = unsafe { slice::from_raw_parts(req_bin, req_length) };
    let action_req: sgxwasm::SgxWasmAction = serde_json::from_slice(req_slice).unwrap();

    let response;
    let return_status;

    match action_req {
        sgxwasm::SgxWasmAction::Invoke{module,field,args}=> {
            let args = args.into_iter()
                           .map(|x| boundary_value_to_runtime_value(x))
                           .collect::<Vec<RuntimeValue>>();
            let r = wasm_invoke(module, field, args);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
               }
            }
        },
        sgxwasm::SgxWasmAction::Get{module,field} => {
            let r = wasm_get(module, field);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_v) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::LoadModule{name,module} => {
            let r = wasm_load_module(name.clone(), module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::TryLoad{module} => {
            let r = wasm_try_load(module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR;
                }
            }
        },
        sgxwasm::SgxWasmAction::Register{name, as_name} => {
            let r = wasm_register(&name, as_name.clone());
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR;
                }
            }
        }
    }

    //println!("len = {}, Response = {:?}", response.len(), response);

    if response.len() < result_max_len {
        unsafe {
            ptr::copy_nonoverlapping(response.as_ptr(),
                                     result_bin,
                                     response.len());
        }
        return return_status;
    }
    else{
        //println!("Result len = {} > buf size = {}", response.len(), result_max_len);
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }
}

