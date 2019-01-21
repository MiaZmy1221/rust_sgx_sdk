use func::FuncRef;
use core::fmt;
use std::vec::Vec;
use std::string::String;

/// This is a new added file: message.rs, which is used for representing messages between two modules/actors.

/// Changes compared to the previous file:
///
/// 1) Implement a struct Message. A message contains 5 fields: 
///    function name, function name's length, parameters and its length, codeid and dataid.
///    All its fields and functions are public.
#[derive(Debug, Clone)]
pub struct Message {
	pub function: String,
	pub args: Vec<i32>,
	pub func_len: i32,
	pub args_len: i32,
	pub codeid: i32,
	pub dataid: i32,
}

impl Message {
	pub fn new(func: String, func_l: i32, arg: Vec<i32>, args_l: i32, mid: i32, cid: i32) -> Message {
		Message {
			function: func,
			func_len: func_l,
			args: arg,
			args_len: args_l,
			codeid: mid,
			dataid: cid,
		}
	}
}

