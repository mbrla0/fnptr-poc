//! Supporting code.
//!

include!(concat!(env!("OUT_DIR"), "/sup.rs"));

use std::ffi::CStr;
use std::fmt::Formatter;
use std::io::Result as IoResult;

/// ptrace(2) that returns an [`IoResult<libc::c_long>`].
macro_rules! _rptrace {
	($($args:expr),+$(,)?) => {{
		crate::sup::clear_errno();
		let result = libc::ptrace($($args),+);
		let errno = crate::sup::read_errno();

		if result == -1 && errno != 0 {
			Err(std::io::Error::from_raw_os_error(errno))
		} else {
			Ok(result)
		}
	}}
}
pub(crate) use _rptrace as rptrace;

/// Defers execution of the given expression until the value returned by this
/// macro is dropped.
///
/// Hopefully.
macro_rules! defer {
    ($expr:expr) => {{
		struct Defer<F: FnMut()>(F);
		impl<F> Drop for Defer<F>
			where F: FnMut() {

			fn drop(&mut self) {
				(self.0)();
			}
		}
		Defer(|| { $expr })
	}};
}

#[derive(Debug)]
pub struct CapstoneError(capstone_sys::cs_err::Type, bool);
impl CapstoneError {
	fn new(code: capstone_sys::cs_err::Type) -> Self {
		/* These only go as high as 14 for now. See `cs_err`.
		 *
		 * We _really_ don't want to be calling cs_* functions with nonsense
		 * parameters, so we chicken out completely here if the number is too
		 * high. */
		Self(code, code <= 14)
	}
}
impl std::fmt::Display for CapstoneError {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let mut str = "Unknown Error".to_owned();

		if self.1 {
			unsafe {
				let c_str = capstone_sys::cs_strerror(self.0);
				if !c_str.is_null() {
					str = CStr::from_ptr(c_str)
						.to_string_lossy()
						.into_owned();
				}
			}
		};

		write!(f, "{} ({:#x})", str, self.0)
	}
}
impl std::error::Error for CapstoneError {}

/// Captures errors in Capstone.
pub fn cs_catch(ret: capstone_sys::cs_err::Type) -> Result<(), CapstoneError> {
	if ret != capstone_sys::cs_err::CS_ERR_OK {
		Err(CapstoneError::new(ret))
	} else {
		Ok(())
	}
}

/// Equivalent to `NULL` in C.
pub const fn nullptr() -> *mut libc::c_void {
	std::ptr::null_mut()
}

/// Reads the registers of an inferior process.
pub unsafe fn regs_of(pid: libc::pid_t) -> IoResult<libc::user_regs_struct> {
	let mut regs = std::mem::zeroed::<libc::user_regs_struct>();
	rptrace!(libc::PTRACE_GETREGS, pid, nullptr(), &mut regs as *mut _)?;

	Ok(regs)
}

/// Writes the registers of an inferior process.
pub unsafe fn set_regs_of(pid: libc::pid_t, regs: &libc::user_regs_struct) -> IoResult<()> {
	rptrace!(libc::PTRACE_SETREGS, pid, nullptr(), regs as *const _).map(|_| ())
}

/// Reads the program counter of an inferior process.
pub unsafe fn pc_of(pid: libc::pid_t) -> IoResult<libc::c_ulonglong> {
	regs_of(pid).map(|regs| regs.rip)
}

/// Reads the program counter of an inferior process.
pub unsafe fn set_pc_of(pid: libc::pid_t, pc: libc::c_ulonglong) -> IoResult<()> {
	let mut regs = regs_of(pid)?;
	regs.rip = pc;

	set_regs_of(pid, &regs)
}

/// Run ptrace(2) but return `Ok(count)` if `errno` is [`libc::EIO`].
macro_rules! rptrace_bail_eio {
	(count: $count:expr, args: ($($args:expr),+$(,)?)) => {
		match _rptrace!($($args),+) {
			Ok(result) => result,
			Err(what) if what.raw_os_error().unwrap() == libc::EIO =>
				return Ok($count),
			Err(what) => return Err(what)
		}
	}
}

/// Writes to the virtual memory space of an inferior process.
pub unsafe fn vm_write(pid: libc::pid_t, offset: libc::uintptr_t, data: &[u8]) -> IoResult<usize> {
	let transfer_block = std::mem::size_of::<libc::uintptr_t>();
	let mut count = 0usize;

	let leading = ((transfer_block - offset % transfer_block) % transfer_block).min(data.len());
	let whole_transfers = (data.len() - leading) / transfer_block;
	let trailing = (data.len() - leading) % transfer_block;

	/* Handle the leading bytes. */
	if leading != 0 {
		let base = offset - offset % transfer_block;

		let word = rptrace_bail_eio!{
			count: count,
			args: (
				libc::PTRACE_PEEKTEXT,
				pid,
				base,
				nullptr()
			)
		};
		let mut word = word.to_ne_bytes();
		for i in 0..leading {
			word[offset % transfer_block + i] = data[i];
		}
		let word = libc::uintptr_t::from_ne_bytes(word);

		let _ = rptrace_bail_eio! {
			count: count,
			args: (
				libc::PTRACE_POKEDATA,
				pid,
				base,
				word,
			)
		};
		count += leading;
	}

	/* Handle the trunk of the transfer. */
	for _ in 0..whole_transfers {
		let data = &data[count..count + transfer_block];
		let data = data.try_into().unwrap();

		let word = libc::uintptr_t::from_ne_bytes(data);

		/* This call is a _little_ terrifying. We actually pass uintptr_t to
		 * ptrace(2) rather than the pointer it's technically expecting to get. */
		let _ = rptrace_bail_eio! {
			count: count,
			args: (
				libc::PTRACE_POKEDATA,
				pid,
				offset + count,
				word,
			)
		};
		count += transfer_block;
	}

	/* Handle the trailing bytes. */
	if trailing != 0 {
		let word = rptrace_bail_eio! {
			count: count,
			args: (
				libc::PTRACE_PEEKTEXT,
				pid,
				offset + count,
				nullptr()
			)
		};

		let mut word = word.to_ne_bytes();
		for i in 0..trailing {
			word[i] = data[count + i];
		}

		let data = libc::uintptr_t::from_ne_bytes(word);
		let _ = rptrace_bail_eio! {
			count: count,
			args: (
				libc::PTRACE_POKEDATA,
				pid,
				offset + count,
				data
			)
		};
	}

	Ok(data.len())
}

/// Reads from the virtual memory space of an inferior process.
pub unsafe fn vm_read(pid: libc::pid_t, offset: libc::uintptr_t, data: &mut [u8]) -> IoResult<usize> {
	let transfer_block = std::mem::size_of::<libc::uintptr_t>();
	let mut count = 0usize;

	let leading = ((transfer_block - offset % transfer_block) % transfer_block).min(data.len());
	let whole_transfers = (data.len() - leading) / transfer_block;
	let trailing = (data.len() - leading) % transfer_block;

	/* Handle the leading bytes. */
	if leading != 0 {
		let base = offset - offset % transfer_block;

		let word = rptrace_bail_eio!{
			count: count,
			args: (
				libc::PTRACE_PEEKTEXT,
				pid,
				base,
				nullptr()
			)
		};
		let word = word.to_ne_bytes();
		for i in 0..leading {
			data[i] = word[offset % transfer_block + i];
		}
		count += leading;
	}

	/* Handle the trunk of the transfer. */
	for _ in 0..whole_transfers {
		let word = rptrace_bail_eio! {
			count: count,
			args: (
				libc::PTRACE_PEEKTEXT,
				pid,
				offset + count,
				nullptr()
			)
		};
		data[count..count + transfer_block].copy_from_slice(&word.to_ne_bytes());

		count += transfer_block;
	}

	/* Handle the trailing bytes. */
	if trailing != 0 {
		let word = rptrace_bail_eio! {
			count: count,
			args: (
				libc::PTRACE_PEEKTEXT,
				pid,
				offset + count,
				nullptr()
			)
		};

		let word = word.to_ne_bytes();
		for i in 0..trailing {
			data[count + i] = word[i];
		}
	}

	Ok(data.len())
}

/// Disassembles instructions from the virtual memory space of an inferior process.
pub unsafe fn vm_disasm_for_each<F>(
	handle: capstone_sys::csh,
	insn: *mut capstone_sys::cs_insn,
	pid: libc::pid_t,
	offset: libc::uintptr_t,
	mut f: F,
) -> IoResult<()>
	where F: FnMut(&capstone_sys::cs_insn, libc::uintptr_t) -> bool {

	/* Allocate the buffer that holds raw instruction data. */
	const BUFFER_SIZE: usize = 256;

	let layout = std::alloc::Layout::new::<[u8; BUFFER_SIZE]>();
	let buffer = std::alloc::alloc(layout);
	if buffer.is_null() { std::alloc::handle_alloc_error(layout) }
	let _def0 = defer! { std::alloc::dealloc(buffer, layout) };

	/* Iterate over the disassembly. */
	let mut cursor = buffer;
	let mut end = buffer;
	let mut needs_more_data = true;
	let mut displacement = 0usize;
	let mut address = offset as u64;
	loop {
		if needs_more_data {
			let preserve = end.offset_from(cursor);
			debug_assert!(preserve >= 0);

			std::ptr::copy(cursor, buffer, preserve as usize);

			cursor = buffer;
			end = cursor.offset(preserve);

			let read = vm_read(
				pid,
				offset + displacement,
				std::slice::from_raw_parts_mut(
					buffer.offset(preserve),
					BUFFER_SIZE - preserve as usize
				)
			)?;
			if read == 0 {
				/* There's no way to move forward. */
				break
			}
			displacement += read;

			end = end.offset(read as isize);
		}

		let current_addr = address;
		let mut size = end.offset_from(cursor) as usize;
		needs_more_data = !capstone_sys::cs_disasm_iter(
			handle,
			&mut cursor as *mut *mut _ as *mut *const _,
			&mut size as *mut _,
			&mut address as *mut _,
			insn);

		if !needs_more_data {
			/* This is a valid instruction, let the consumer handle it. */
			if !f(&*insn, current_addr as _) { break }
		}
	}

	Ok(())
}

/// Read the value of the register represented by the given Capstone enum variant.
pub fn cs_reg(cs: capstone_sys::x86_reg::Type, regs: &libc::user_regs_struct) -> libc::c_ulonglong {
	match cs {
		capstone_sys::x86_reg::X86_REG_RAX => regs.rax,
		capstone_sys::x86_reg::X86_REG_EAX => regs.rax & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_AX  => regs.rax & 0xffff,
		capstone_sys::x86_reg::X86_REG_AH  => (regs.rax & 0xff00) >> 8,
		capstone_sys::x86_reg::X86_REG_AL  => regs.rax & 0xff,

		capstone_sys::x86_reg::X86_REG_RBX => regs.rbx,
		capstone_sys::x86_reg::X86_REG_EBX => regs.rbx & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_BX  => regs.rbx & 0xffff,
		capstone_sys::x86_reg::X86_REG_BH  => (regs.rbx & 0xff00) >> 8,
		capstone_sys::x86_reg::X86_REG_BL  => regs.rbx & 0xff,

		capstone_sys::x86_reg::X86_REG_RCX => regs.rcx,
		capstone_sys::x86_reg::X86_REG_ECX => regs.rcx & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_CX  => regs.rcx & 0xffff,
		capstone_sys::x86_reg::X86_REG_CH  => (regs.rcx & 0xff00) >> 8,
		capstone_sys::x86_reg::X86_REG_CL  => regs.rcx & 0xff,

		capstone_sys::x86_reg::X86_REG_RDX => regs.rdx,
		capstone_sys::x86_reg::X86_REG_EDX => regs.rdx & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_DX  => regs.rdx & 0xffff,
		capstone_sys::x86_reg::X86_REG_DH  => (regs.rdx & 0xff00) >> 8,
		capstone_sys::x86_reg::X86_REG_DL  => regs.rdx & 0xff,

		capstone_sys::x86_reg::X86_REG_RDI => regs.rdi,
		capstone_sys::x86_reg::X86_REG_EDI => regs.rdi & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_DI  => regs.rdi & 0xffff,
		capstone_sys::x86_reg::X86_REG_DIL => regs.rdi & 0xff,

		capstone_sys::x86_reg::X86_REG_RSI => regs.rsi,
		capstone_sys::x86_reg::X86_REG_ESI => regs.rsi & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_SI  => regs.rsi & 0xffff,
		capstone_sys::x86_reg::X86_REG_SIL => regs.rsi & 0xff,

		capstone_sys::x86_reg::X86_REG_RSP => regs.rsp,
		capstone_sys::x86_reg::X86_REG_ESP => regs.rsp & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_SP  => regs.rsp & 0xffff,
		capstone_sys::x86_reg::X86_REG_SPL => regs.rsp & 0xff,

		capstone_sys::x86_reg::X86_REG_RBP => regs.rbp,
		capstone_sys::x86_reg::X86_REG_EBP => regs.rbp & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_BP  => regs.rbp & 0xffff,
		capstone_sys::x86_reg::X86_REG_BPL => regs.rbp & 0xff,

		capstone_sys::x86_reg::X86_REG_R8  => regs.r8,
		capstone_sys::x86_reg::X86_REG_R8D => regs.r8 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R8W => regs.r8 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R8B => regs.r8 & 0xff,

		capstone_sys::x86_reg::X86_REG_R9  => regs.r9,
		capstone_sys::x86_reg::X86_REG_R9D => regs.r9 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R9W => regs.r9 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R9B => regs.r9 & 0xff,

		capstone_sys::x86_reg::X86_REG_R10  => regs.r10,
		capstone_sys::x86_reg::X86_REG_R10D => regs.r10 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R10W => regs.r10 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R10B => regs.r10 & 0xff,

		capstone_sys::x86_reg::X86_REG_R11  => regs.r11,
		capstone_sys::x86_reg::X86_REG_R11D => regs.r11 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R11W => regs.r11 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R11B => regs.r11 & 0xff,

		capstone_sys::x86_reg::X86_REG_R12  => regs.r12,
		capstone_sys::x86_reg::X86_REG_R12D => regs.r12 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R12W => regs.r12 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R12B => regs.r12 & 0xff,

		capstone_sys::x86_reg::X86_REG_R13  => regs.r13,
		capstone_sys::x86_reg::X86_REG_R13D => regs.r13 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R13W => regs.r13 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R13B => regs.r13 & 0xff,

		capstone_sys::x86_reg::X86_REG_R14  => regs.r14,
		capstone_sys::x86_reg::X86_REG_R14D => regs.r14 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R14W => regs.r14 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R14B => regs.r14 & 0xff,

		capstone_sys::x86_reg::X86_REG_R15  => regs.r15,
		capstone_sys::x86_reg::X86_REG_R15D => regs.r15 & 0xffffffff,
		capstone_sys::x86_reg::X86_REG_R15W => regs.r15 & 0xffff,
		capstone_sys::x86_reg::X86_REG_R15B => regs.r15 & 0xff,
		_ => panic!("invalid Capstone x86 register variant: {cs}")
	}
}
