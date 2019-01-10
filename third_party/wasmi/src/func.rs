use std::prelude::v1::*;
//use std::rc::{Rc, Weak};
use std::sync::{Arc, Weak};
use std::fmt;
use parity_wasm::elements::Local;
use {Trap, TrapKind, Signature};
use host::Externals;
use runner::{check_function_args, Interpreter, InterpreterState};
use value::RuntimeValue;
use types::ValueType;
use module::ModuleInstance;
use isa;

/// Changes compared to the previous file:
///
/// 1) Mainly add implementations of PartialEq for some objects so that we can compare two func objects.
/// 2) Add a function called is_internal to check whether a function is 'internal' or 'host'.


/// Reference to a function (See [`FuncInstance`] for details).
///
/// This reference has a reference-counting semantics.
///
/// [`FuncInstance`]: struct.FuncInstance.html
#[derive(Clone, Debug)]
pub struct FuncRef(Arc<FuncInstance>);

impl ::std::ops::Deref for FuncRef {
	type Target = FuncInstance;
	fn deref(&self) -> &FuncInstance {
		&self.0
	}
}

/// A property for comparing two objects.
///
/// Comparing the following order:
/// FuncRef -> FuncInstance -> FuncBody and FuncSignature.
impl PartialEq for FuncRef {
    fn eq(&self, other: &FuncRef) -> bool {
        let func1 = &self.0;
        let func2 = &other.0;
        func1 == func2
    }
}


/// Runtime representation of a function.
///
/// Functions are the unit of organization of code in WebAssembly. Each function takes a sequence of values
/// as parameters and either optionally return a value or trap.
/// Functions can call other function including itself (i.e recursive calls are allowed) and imported functions
/// (i.e functions defined in another module or by the host environment).
///
/// Functions can be defined either:
///
/// - by a wasm module,
/// - by the host environment and passed to a wasm module as an import.
///   See more in [`Externals`].
///
/// [`Externals`]: trait.Externals.html
pub struct FuncInstance(FuncInstanceInternal);

#[derive(Clone)]
pub(crate) enum FuncInstanceInternal {
	Internal {
		signature: Arc<Signature>,
		module: Weak<ModuleInstance>,
		body: Arc<FuncBody>,
	},
	Host {
		signature: Signature,
		host_func_index: usize,
	},
}

impl fmt::Debug for FuncInstance {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.as_internal() {
			&FuncInstanceInternal::Internal {
				ref signature,
				ref body,
				..
			} => {
				// We can't write description of self.module here, because it generate
				// debug string for function instances and this will lead to infinite loop.
				write!(
					f,
					"Internal {{ signature={:?} body={:?} }}",
					signature,
					body,
				)
			}
			&FuncInstanceInternal::Host { ref signature, .. } => {
				write!(f, "Host {{ signature={:?} }}", signature)
			}
		}
	}
}

/// A property for comparing two objects.
///
/// If those two FuncInstances are both 'internal', compare their func bodys and signatures. If equal, return ture.
/// If those two FuncInstances are both 'host', return false directly.
/// In other cases, return false.
impl PartialEq for FuncInstance {
    fn eq(&self, other: &FuncInstance) -> bool {
        let func1 = self.is_internal();
        let func2 = other.is_internal();
        if func1 == true && func2 == true {
        	let body1 = self.body();
        	let body2 = other.body();
        	let signature1 = self.signature();
        	let signature2 = other.signature();
        	if body1 == body2 && signature1 == signature2 {
        		return true;
        	}
        }
        if func1 == false && func2 == false {
        	return false;
        }
        return false;
    }
}


impl FuncInstance {
	/// Allocate a function instance for a host function.
	///
	/// When this function instance will be called by the wasm code,
	/// the instance of [`Externals`] will be invoked by calling `invoke_index`
	/// with specified `host_func_index` here.
	/// This call will be made with the `signature` provided here.
	///
	/// [`Externals`]: trait.Externals.html
	pub fn alloc_host(signature: Signature, host_func_index: usize) -> FuncRef {
		let func = FuncInstanceInternal::Host {
			signature,
			host_func_index,
		};
		FuncRef(Arc::new(FuncInstance(func)))
	}

	/// Returns [signature] of this function instance.
	///
	/// This function instance can only be called with matching signatures.
	///
	/// [signature]: struct.Signature.html
	pub fn signature(&self) -> &Signature {
		match *self.as_internal() {
			FuncInstanceInternal::Internal { ref signature, .. } => signature,
			FuncInstanceInternal::Host { ref signature, .. } => signature,
		}
	}

	pub fn get_return_type(&self) -> bool {
		let signature = self.signature();
		let return_type = signature.return_type();
		if return_type == None {
			return false;
		}
		return true;
	}

	pub(crate) fn as_internal(&self) -> &FuncInstanceInternal {
		&self.0
	}

	pub(crate) fn alloc_internal(
		module: Weak<ModuleInstance>,
		signature: Arc<Signature>,
		body: FuncBody,
	) -> FuncRef {
		let func = FuncInstanceInternal::Internal {
			signature,
			module: module,
			body: Arc::new(body),
		};
		FuncRef(Arc::new(FuncInstance(func)))
	}

	pub(crate) fn body(&self) -> Option<Arc<FuncBody>> {
		match *self.as_internal() {
			FuncInstanceInternal::Internal { ref body, .. } => Some(Arc::clone(body)),
			FuncInstanceInternal::Host { .. } => None,
		}
	}

	/// Determine whether this FuncInstance is 'internal' or 'host'.
	/// 
	/// This funcion is added for implementing "impl PartialEq for FuncInstance".
	pub fn is_internal(&self) -> bool {
		match *self.as_internal() {
			FuncInstanceInternal::Internal { .. } => true,
			FuncInstanceInternal::Host { .. } => false,
		}
	}

	/// Invoke this function.
	///
	/// # Errors
	///
	/// Returns `Err` if `args` types is not match function [`signature`] or
	/// if [`Trap`] at execution time occured.
	///
	/// [`signature`]: #method.signature
	/// [`Trap`]: #enum.Trap.html
	pub fn invoke<E: Externals>(
		func: &FuncRef,
		args: &[RuntimeValue],
		externals: &mut E,
	) -> Result<Option<RuntimeValue>, Trap> {
		check_function_args(func.signature(), &args).map_err(|_| TrapKind::UnexpectedSignature)?;
		match *func.as_internal() {
			FuncInstanceInternal::Internal { .. } => {
				let mut interpreter = Interpreter::new(func, args)?;
				interpreter.start_execution(externals)
			}
			FuncInstanceInternal::Host {
				ref host_func_index,
				..
			} => externals.invoke_index(*host_func_index, args.into()),
		}
	}

	/// Invoke the function, get a resumable handle. This handle can then be used to [`start_execution`]. If a
	/// Host trap happens, caller can use [`resume_execution`] to feed the expected return value back in, and then
	/// continue the execution.
	///
	/// This is an experimental API, and this functionality may not be available in other WebAssembly engines.
	///
	/// # Errors
	///
	/// Returns `Err` if `args` types is not match function [`signature`].
	///
	/// [`signature`]: #method.signature
	/// [`Trap`]: #enum.Trap.html
	/// [`start_execution`]: struct.FuncInvocation.html#method.start_execution
	/// [`resume_execution`]: struct.FuncInvocation.html#method.resume_execution
	pub fn invoke_resumable<'args>(
		func: &FuncRef,
		args: &'args [RuntimeValue],
	) -> Result<FuncInvocation<'args>, Trap> {
		check_function_args(func.signature(), &args).map_err(|_| TrapKind::UnexpectedSignature)?;
		match *func.as_internal() {
			FuncInstanceInternal::Internal { .. } => {
				let interpreter = Interpreter::new(func, args)?;
				Ok(FuncInvocation {
					kind: FuncInvocationKind::Internal(interpreter),
				})
			}
			FuncInstanceInternal::Host {
				ref host_func_index,
				..
			} => {
				Ok(FuncInvocation {
					kind: FuncInvocationKind::Host {
						args,
						host_func_index: *host_func_index,
						finished: false,
					},
				})
			},
		}
	}
}

/// A resumable invocation error.
#[derive(Debug)]
pub enum ResumableError {
	/// Trap happened.
	Trap(Trap),
	/// The invocation is not resumable.
	///
	/// Invocations are only resumable if a host function is called, and the host function returns a trap of `Host` kind. For other cases, this error will be returned. This includes:
	/// - The invocation is directly a host function.
	/// - The invocation has not been started.
	/// - The invocation returns normally or returns any trap other than `Host` kind.
	///
	/// This error is returned by [`resume_execution`].
	///
	/// [`resume_execution`]: struct.FuncInvocation.html#method.resume_execution
	NotResumable,
	/// The invocation has already been started.
	///
	/// This error is returned by [`start_execution`].
	///
	/// [`start_execution`]: struct.FuncInvocation.html#method.start_execution
	AlreadyStarted,
}

impl From<Trap> for ResumableError {
	fn from(trap: Trap) -> Self {
		ResumableError::Trap(trap)
	}
}

/// A resumable invocation handle. This struct is returned by `FuncInstance::invoke_resumable`.
pub struct FuncInvocation<'args> {
	kind: FuncInvocationKind<'args>,
}

enum FuncInvocationKind<'args> {
	Internal(Interpreter),
	Host {
		args: &'args [RuntimeValue],
		host_func_index: usize,
		finished: bool
	},
}

impl<'args> FuncInvocation<'args> {
	/// Whether this invocation is currently resumable.
	pub fn is_resumable(&self) -> bool {
		match &self.kind {
			&FuncInvocationKind::Internal(ref interpreter) => interpreter.state().is_resumable(),
			&FuncInvocationKind::Host { .. } => false,
		}
	}

	/// If the invocation is resumable, the expected return value type to be feed back in.
	pub fn resumable_value_type(&self) -> Option<ValueType> {
		match &self.kind {
			&FuncInvocationKind::Internal(ref interpreter) => {
				match interpreter.state() {
					&InterpreterState::Resumable(ref value_type) => value_type.clone(),
					_ => None,
				}
			},
			&FuncInvocationKind::Host { .. } => None,
		}
	}

	/// Start the invocation execution.
	pub fn start_execution<'externals, E: Externals + 'externals>(&mut self, externals: &'externals mut E) -> Result<Option<RuntimeValue>, ResumableError> {
		match self.kind {
			FuncInvocationKind::Internal(ref mut interpreter) => {
				if interpreter.state() != &InterpreterState::Initialized {
					return Err(ResumableError::AlreadyStarted);
				}
				Ok(interpreter.start_execution(externals)?)
			},
			FuncInvocationKind::Host { ref args, ref mut finished, ref host_func_index } => {
				if *finished {
					return Err(ResumableError::AlreadyStarted);
				}
				*finished = true;
				Ok(externals.invoke_index(*host_func_index, args.clone().into())?)
			},
		}
	}

	/// Resume an execution if a previous trap of Host kind happened.
	///
	/// `return_val` must be of the value type [`resumable_value_type`], defined by the host function import. Otherwise,
	/// `UnexpectedSignature` trap will be returned. The current invocation must also be resumable
	/// [`is_resumable`]. Otherwise, a `NotResumable` error will be returned.
	///
	/// [`resumable_value_type`]: #method.resumable_value_type
	/// [`is_resumable`]: #method.is_resumable
	pub fn resume_execution<'externals, E: Externals + 'externals>(&mut self, return_val: Option<RuntimeValue>, externals: &'externals mut E) -> Result<Option<RuntimeValue>, ResumableError> {
		match self.kind {
			FuncInvocationKind::Internal(ref mut interpreter) => {
				if !interpreter.state().is_resumable() {
					return Err(ResumableError::AlreadyStarted);
				}
				Ok(interpreter.resume_execution(return_val, externals)?)
			},
			FuncInvocationKind::Host { .. } => {
				return Err(ResumableError::NotResumable);
			},
		}
	}
}

#[derive(Clone, Debug)]
pub struct FuncBody {
	pub locals: Vec<Local>,
	pub code: isa::Instructions,
}

/// A property for comparing two objects.
///
/// Compare two FuncBody.
/// Actually, we compare a function body's instructions directly here, rather than impl PartialEq for Instructions.
/// For that using trait PartialEq for Instructions, values inside enum Instruction will not be compared. 
/// It may cause some errors. For example: I32Const(17) equals to I32Const(0).
impl PartialEq for FuncBody {
    fn eq(&self, other: &FuncBody) -> bool {
        if self.locals != other.locals {
        	return false;
        }
        for (a, b) in self.code.code.iter().zip(other.code.code.iter()) {
        	if a != b {
        		return false;
        	}
        }
        return true;
    }
}