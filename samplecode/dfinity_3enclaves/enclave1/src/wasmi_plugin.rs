
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
use std::vec::Vec;
use std::string::ToString;

/// Changes to the previous file.(wasmi)
///
/// 1) Define struct DfinityFunc and implement related functions: internalize() and externalize().
///    Clear explainations are as follow.
/// 1.1)  One difference between DfinityData and DfinityFunc is that DfinityFunc needs to preload its funcmap by design. 
///       Function preload_example1() and preload_example2() are for two examples.
///       example1 is that simple.wat's callref() function calls sum.wat's sum2() function, so preload_example1() only loads functions in sum.wat into the funcmap.
///       example2 is that moduleOne.wat's callref() function calls moduleTwo.wat's call_sum() function, then call_sum() function calls moduleThree's sum() function.
///       so preload_example2() only loads functions both in moduleTwo.wat and moduleThree.wat into the funcmap.
/// 2) Changes about DfinityData are the same as DfinityFunc.
///    Another difference is that DfinityData has an extract function length() used to get a given databuf's length.
/// 3) Function run_data() is to run modules with import DfinityData.
/// 4) Function run_func() is to run modules with import DfinityFunc.


#[derive(Clone)]
pub struct DfinityFunc {
    pub table: Option<TableRef>,
    pub funcmap: HashMap<i32, Option<FuncRef>>,
    pub counter: i32,
}

impl fmt::Debug for DfinityFunc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("DfinityFunc")
            .field("table", &self.table)
            .field("funcmap", &self.funcmap)
            .field("counter", &self.counter)
            .finish()
    }
}

/// We assume that all the modules/actors/agents have a shared funcmap that stores all the externalized functions.
/// Right now, we have not implemented this dynamic increasing funcmap.
/// Thus, we preload all the needed functions into the funcmap. 
/// That is, prepare for the funcmap which should contains all the functions we need for calling another module.
fn preload_example1() -> HashMap<i32, Option<FuncRef>> {
    // code2 is sum.wat's bytecode, which contains two functions sum and sum2
    let mut code2: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0d, 0x03, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00, 0x03, 0x03, 0x02, 0x01, 0x02, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x0e, 0x02, 0x03, 0x73, 0x75, 0x6d, 0x00, 0x00, 0x04, 0x73, 0x75, 0x6d, 0x32, 0x00, 0x01, 0x0a, 0x14, 0x02, 0x09, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x24, 0x00, 0x0b, 0x08, 0x00, 0x41, 0x02, 0x41, 0x03, 0x10, 0x00, 0x0b].to_vec();
    let module2 = wasmi::Module::from_buffer(&code2).unwrap();
    let instance2 = ModuleInstance::new(&module2,&ImportsBuilder::default()).expect("Failed to instantiate module").assert_no_start();
    instance2.set_ids_for_funcs(70 as i32, 71 as i32);
    instance2.set_func_name_for_funcs();
    let func_tempt1 = instance2.func_by_index(0).clone().unwrap();
    let func_tempt2 = instance2.func_by_index(1).clone().unwrap();
    let mut default_funcmap = HashMap::new();
    default_funcmap.insert(0 as i32, Some(func_tempt1));
    default_funcmap.insert(1 as i32, Some(func_tempt2));
    default_funcmap
}

/// This example works like moduleOne's function callref calls moduleTwo's call_sum function,
/// then moduleTwo's call_sum function calls moduleThree's function sum.
fn preload_example2() -> HashMap<i32, Option<FuncRef>> {
    // code2 is moduleTwo's bytecode, which contains two functions: one is named call_sum, the other is func.in.
    let mut code2: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x12, 0x04, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x60, 0x00, 0x00, 0x02, 0x14, 0x01, 0x04, 0x66, 0x75, 0x6e, 0x63, 0x0b, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x69, 0x7a, 0x65, 0x00, 0x01, 0x03, 0x02, 0x01, 0x03, 0x04, 0x04, 0x01, 0x70, 0x00, 0x01, 0x07, 0x14, 0x02, 0x05, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x01, 0x00, 0x08, 0x63, 0x61, 0x6c, 0x6c, 0x5f, 0x73, 0x75, 0x6d, 0x00, 0x01, 0x0a, 0x13, 0x01, 0x11, 0x00, 0x41, 0x00, 0x41, 0x02, 0x10, 0x00, 0x41, 0x01, 0x41, 0x03, 0x41, 0x00, 0x11, 0x02, 0x00, 0x0b].to_vec();
    let module2 = wasmi::Module::from_buffer(&code2).unwrap();
    let mut func = DfinityFunc::new_without_funcmap();
    let instance2 = ModuleInstance::new(&module2, &ImportsBuilder::new().with_resolver("func", &func)).expect("Failed to instantiate module").assert_no_start();
    instance2.set_ids_for_funcs(74 as i32, 75 as i32);
    instance2.set_func_name_for_funcs();
    let func_tempt1 = instance2.func_by_index(0).clone().unwrap();
    let func_tempt2 = instance2.func_by_index(1).clone().unwrap();
    let mut default_funcmap = HashMap::new();
    default_funcmap.insert(0 as i32, Some(func_tempt1));
    default_funcmap.insert(1 as i32, Some(func_tempt2));

    // code3 is moduleThree's bytecode, which contains only one function: sum() add two constants and store the result into the $g
    let mut code3: Vec<u8> = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x01, 0x7f, 0x00, 0x60, 0x02, 0x7f, 0x7f, 0x00, 0x03, 0x02, 0x01, 0x01, 0x06, 0x06, 0x01, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x07, 0x01, 0x03, 0x73, 0x75, 0x6d, 0x00, 0x00, 0x0a, 0x0b, 0x01, 0x09, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x24, 0x00, 0x0b].to_vec();    
    let module3 = wasmi::Module::from_buffer(&code3).unwrap();
    
    let instance3 = ModuleInstance::new(&module3, &ImportsBuilder::default()).expect("Failed to instantiate module").assert_no_start();
    instance3.set_ids_for_funcs(76 as i32, 77 as i32);
    instance3.set_func_name_for_funcs();
    let func_tempt3 = instance3.func_by_index(0).clone().unwrap();
    default_funcmap.insert(2 as i32, Some(func_tempt3));

    default_funcmap
}


impl DfinityFunc {
    pub fn new_without_funcmap() -> DfinityFunc {
        DfinityFunc {
            table: Some(TableInstance::alloc(1, None).unwrap()),
            funcmap: HashMap::new(),
            counter: 0,
        }
    }
    pub fn new() -> DfinityFunc {
        // let mut default_funcmap = preload_example1();
        let mut default_funcmap = preload_example1();
        DfinityFunc {
            table: Some(TableInstance::alloc(1, None).unwrap()),
            funcmap: default_funcmap,
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
                let func = table.get(a).unwrap();
                let tempt_func = func.clone().unwrap();
                let flag = (*tempt_func).get_return_type();
                if flag == false {
                    println!("Error because there shoube be no return value in the function");
                }
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
    pub fn new() -> DfinityData {
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


/// Execute dfinity_data.wast file.
///
/// Workflow is as follows:
/// Step1: instantiate the module from buffer(bytecode) directly and form a parity module.
/// Step2: new a mut struct DfinityFunc and DfinityData.
/// Step3: transfer the parity module to a module in wasmi.
/// Step4: add data to the module's memory.
/// Step5: before before invoking the function, get the module's exported memory and assign it to the struct's memory field.
/// Step6: invoke the function with the given function name and its parameters.
/// Step7: get messages if any. If message_check equals -1, this means there is no message; else the message_check represents the func index in the table.
/// Step8: get the revised memor, assign it to the parameter data_buf, then return to the MessageArray.
///        actually, the wast file that does not contain func struct will not produce any new message, so the messageArray is empty.
pub fn run_data(code: &mut Vec<u8>, data_buf: &mut Vec<u8>, wasm_func: &str, wasm_args: Vec<i32>) -> Vec<Message> {
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
    println!("After invoking function, instance is {:?}", instance);

    let mut messageArray = Vec::new();
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
        let func_ref = func.clone().table.unwrap().get(message_bool as u32).unwrap();
        let tempt_func_ref = func_ref.clone().unwrap();
        let func_name = (*tempt_func_ref).get_name();
        let (mid, did) = (*tempt_func_ref).get_ids();
        let args_len = (*tempt_func_ref).get_params_len();
        let func_name_final = (*func_name).borrow_mut().to_string();
        let func_len_final = (*func_name).borrow_mut().to_string().len() as i32;
        let mid_final = (*mid).get();
        let did_final = (*did).get();
        let temptMessage = Message::new(func_name_final, func_len_final, args, args_len, mid_final, did_final);
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
/// Step2: new a mut struct DfinityFunc.
/// Step3: transfer the parity module to a module in wasmi.
/// Step4: If this module does not contain a memory, add one. Then add data field to the module's memory.
/// Step5: Add codeid, dataid and name for every function in the module. 
/// Step6: Check whether the module contains a table export in the exports section and if not, add one.
///        Then before before invoking the function, get the module's exported table and assign it to the struct's table field.
/// Step7: invoke the function with the given function name and its parameters.
/// Step8: get messages if any. If message_check equals -1, this means there is no message; else the message_check represents the func index in the table.
/// Step9: get the revised memory, assign it to the parameter data_buf, then return to the MessageArray.

pub fn run_func(code: &mut Vec<u8>, data_buf: &mut Vec<u8>, wasm_func: &str, wasm_args: Vec<i32>, codeid: i32, dataid: i32) -> Vec<Message> {
    let module = wasmi::Module::from_buffer(&code).unwrap();
    let mut func = DfinityFunc::new();

    let instance = ModuleInstance::new(&module, &ImportsBuilder::new().with_resolver("func", &func),).expect("Failed to instantiate module").assert_no_start();
    
    if (module.module().memory_section() == None){
        let new_memory = MemoryInstance::alloc(Pages(1), None).expect("Due to validation `initial` and `maximum` should be valid");
        instance.push_memory(new_memory);
    }
    let memory = instance.memory_by_index(0).expect("this is the memory of this instance");
    memory.set(0, &data_buf);

    instance.set_ids_for_funcs(codeid, dataid);
    instance.set_func_name_for_funcs();

    instance.exports_has_table();
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
    println!("After invoking function, instance is {:?}", instance);

    let mut messageArray = Vec::new();
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
        let func_ref = func.clone().table.unwrap().get(message_bool as u32).unwrap();
        let tempt_func_ref = func_ref.clone().unwrap();
        let func_name = (*tempt_func_ref).get_name();
        let (mid, did) = (*tempt_func_ref).get_ids();
        let args_len = (*tempt_func_ref).get_params_len();
        let func_name_final = (*func_name).borrow_mut().to_string();
        let func_len_final = (*func_name).borrow_mut().to_string().len() as i32;
        let mid_final = (*mid).get();
        let did_final = (*did).get();
        let temptMessage = Message::new(func_name_final, func_len_final, args, args_len, mid_final, did_final);
        messageArray.push(temptMessage);
    }
    data_buf.truncate(0);
    let revised_memory = instance.memory_by_index(0).unwrap().get_whole_buf().unwrap();
    data_buf.extend(revised_memory.iter().cloned());
    messageArray
}
