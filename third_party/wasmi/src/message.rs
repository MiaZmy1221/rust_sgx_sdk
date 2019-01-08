use func::FuncRef;
use core::fmt;
use std::vec::Vec;

/// Changes compared to the previous file:
///
/// 1) This is a new added file: message.rs, which is used for representing messages between two modules/actors.

/// A message contains two parts: called function and its arguments.
#[derive(Debug)]
pub struct Message {
	function: Option<FuncRef>,
	args: Vec<i32>,
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
	msgArray: Vec<Message>,
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
	fn length(&self) -> usize {
		self.msgArray.len()
	} 

	/// Check whether the message array is empty or not.
	fn is_empty(&self) -> bool {
		self.msgArray.is_empty()
	} 

	/// Get a message with the given index.
	fn get(&self, index: usize) -> &Message {
		self.msgArray.get(index).unwrap()
	} 

	/// Push a message into the message array.
	pub fn push(&mut self, message: Message) {
		self.msgArray.push(message);
	}
}
