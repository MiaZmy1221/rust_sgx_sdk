use func::FuncRef;
use core::fmt;
use std::vec::Vec;

/// This is a new added file: message.rs, which is used for representing messages between two modules/actors.

/// Changes compared to the previous file:
///
/// 1) Implement a struct Message. A message contains two parts: called function and its arguments.
///    All its fields and functions are public.
/// 2) Implement a struct MessageArray, which is a list of messages. 
///    Also implement some functions for this struct.
#[derive(Debug, Clone)]
pub struct Message {
	pub function: Option<FuncRef>,
	pub args: Vec<i32>,
}

impl Message {
	pub fn new(func: Option<FuncRef>, arg: Vec<i32>) -> Message {
		Message {
			function: func,
			args: arg,
		}
	}
}

/// A MessageArray is the list of messages, every actor has its own MessageArray to maintain all the related messages.
pub struct MessageArray {
	pub msgArray: Vec<Message>,
}


impl fmt::Debug for MessageArray {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("MessageArray")
			.field("msgArray", &self.msgArray)
			.field("array.len", &self.length())
			.finish()
	}
}

impl MessageArray {
	/// New a message.
	pub fn new() -> MessageArray {
		MessageArray {
			msgArray: Vec::new(),
		}
	}

	/// Get length of the message array.
	pub fn length(&self) -> usize {
		self.msgArray.len()
	} 

	/// Check whether the message array is empty or not.
	pub fn is_empty(&self) -> bool {
		self.msgArray.is_empty()
	} 

	/// Get a message with the given index.
	pub fn get(&self, index: usize) -> &Message {
		self.msgArray.get(index).unwrap()
	} 

	/// Push a message into the message array.
	pub fn push(&mut self, message: Message) {
		self.msgArray.push(message);
	}
}
