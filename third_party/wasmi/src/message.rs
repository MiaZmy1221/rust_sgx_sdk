use func::FuncRef;
use core::fmt;
use std::vec::Vec;

#[derive(Debug)]
pub struct Message {
	//fields 
	
	//ActorID
	
	//function signature
	function: Option<FuncRef>,

	//arguments
	args: Vec<i32>,
}

impl Message {
	pub fn new(func: Option<FuncRef>, arg: Vec<i32>) -> Message {
		Message {
			//
			function: func,
			args: arg,
		}
	}
}

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
	pub fn new() -> MessageArray {
		MessageArray {
			msgArray: Vec::new(),
		}
	}

	//get length
	fn length(&self) -> usize {
		self.msgArray.len()
	} 

	fn is_empty(&self) -> bool {
		self.msgArray.is_empty()
	} 

	//get length
	fn get(&self, index: usize) -> &Message {
		self.msgArray.get(index).unwrap()
	} 

	pub fn push(&mut self, message: Message) {
		self.msgArray.push(message);
	}
}
