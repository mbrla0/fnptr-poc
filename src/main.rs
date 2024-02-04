mod sup;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;

fn main() {
	/* Prepare the arguments for the program we're gonna spawn. */
	let mut command = std::env::args_os().skip(1)
		.map(|os_str| CString::new(os_str.as_encoded_bytes()))
		.collect::<Result<Vec<_>, _>>()
		.unwrap()
		.into_iter()
		.map(|c_str| c_str.into_raw())
		.collect::<Vec<_>>();

	if command.len() == 0 {
		eprintln!("Usage: {} <progname> [args]*", std::env::args().next().unwrap());
		std::process::exit(1)
	}

	/* Copy the name of the program. We don't mutate this pointer in any way,
	 * so the alias with the first value of argv is fine. */
	let progname = command[0];

	command.push(std::ptr::null_mut());
	let argv = Box::leak(command.into_boxed_slice()).as_mut_ptr();

	/* Fork and run both the tracker and the child process. */
	let result = unsafe { libc::fork() };
	if result < 0 {
		eprintln!("fork(): {}", result);
		std::process::exit(1)
	}

	unsafe {
		match result {
			0 => child(progname, argv as *const *const libc::c_char),
			child_pid => tracker_loop(child_pid).unwrap()
		}
	}
}

enum JumpTrap {
	/// This jump may be taken with no extra processing.
	Direct {
		/// The raw instruction data.
		instruction: Box<[u8]>
	},
	Indirect {
		/// The raw instruction data.
		instruction: Box<[u8]>,
		/// Calculates the target address, if this is an indirect jump trap.
		target: Arc<dyn Fn(libc::user_regs_struct) -> libc::uintptr_t>
	}
}

#[derive(Debug, Copy, Clone)]
enum TrackerLoopState {
	Setup,

	Idle,
	JumpTrapSingleStep(libc::c_ulonglong),
}

struct Tracker {
	cs: capstone_sys::csh,
	child: libc::pid_t,

	jump_traps: BTreeMap<libc::c_ulonglong, JumpTrap>,

	loop_state: TrackerLoopState
}
impl Tracker {
	pub unsafe fn new(child: libc::pid_t) -> anyhow::Result<Self> {
		let mut cs = std::mem::zeroed();
		sup::cs_catch(capstone_sys::cs_open(
			capstone_sys::cs_arch::CS_ARCH_X86,
			capstone_sys::CS_MODE_64,
			&mut cs as *mut _))?;
		sup::cs_catch(capstone_sys::cs_option(cs, capstone_sys::cs_opt_type::CS_OPT_DETAIL, 1))?;

		Ok(Self {
			cs,
			child,
			jump_traps: Default::default(),
			loop_state: TrackerLoopState::Setup,
		})
	}

	pub unsafe fn handle_exec_trap(&mut self) -> anyhow::Result<()> {
		/* Bootstrap the handling of code. */
		self.handle_landing_pad()
	}

	unsafe fn handle_landing_pad(&mut self) -> anyhow::Result<()> {
		let pc = sup::pc_of(self.child)?;

		println!("[*] Analyzing block at {pc:#x}");

		/* Iterate over the instructions in this block until we reach a branch. */
		let instruction = capstone_sys::cs_malloc(self.cs);
		if instruction.is_null() {
			anyhow::bail!("cs_malloc() returned NULL")
		}
		let mut next_trap = None;
		sup::vm_disasm_for_each(
			self.cs,
			instruction,
			self.child,
			pc as _,
			|insn, address| {
				debug_assert!(!insn.detail.is_null());
				let detail = &*insn.detail;

				print!("[*]    {address:#x} -> ");
				for byte in &insn.bytes[..usize::from(insn.size)] {
					print!("{byte:02x} ")
				}

				/* Check if this is a branch instruction and skip it if not. */
				let flavor = (0..detail.groups_count).into_iter()
					.map(|i| detail.groups[usize::from(i)])
					.fold(0, |selected, candidate| match (selected, candidate as _) {
						(0, capstone_sys::x86_insn_group::X86_GRP_JUMP) => capstone_sys::x86_insn_group::X86_GRP_JUMP,
						(_, capstone_sys::x86_insn_group::X86_GRP_CALL) => capstone_sys::x86_insn_group::X86_GRP_CALL,
						(_, capstone_sys::x86_insn_group::X86_GRP_RET) => capstone_sys::x86_insn_group::X86_GRP_RET,
						_ => selected
					});
				if flavor == 0 { println!(); return true }
				print!("BRANCH ");

				/* Save the instruction bytes, so it can be restored later. */
				let bytes = insn.bytes[..usize::from(insn.size)]
					.to_owned()
					.into_boxed_slice();

				/* Set up the correct jump trap structure for this branch. */
				let x86 = &detail.__bindgen_anon_1.x86;
				let trap = match flavor {
					capstone_sys::x86_insn_group::X86_GRP_RET => {
						/* Catch cases where we've assumed the number of operands wrongly. */
						assert_eq!(x86.op_count, 0);
						println!("DIRECT");
						JumpTrap::Direct { instruction: bytes }
					},
					capstone_sys::x86_insn_group::X86_GRP_CALL
						| capstone_sys::x86_insn_group::X86_GRP_JUMP => {

						/* Catch cases where we've assumed the number of operands wrongly. */
						assert_eq!(x86.op_count, 1);

						let op = &x86.operands[0];
						match op.type_ {
							capstone_sys::x86_op_type::X86_OP_REG => {
								/* Certainly an indirect jump. */
								let reg = op.__bindgen_anon_1.reg;
								let target = Arc::new(move |regs| {
									sup::cs_reg(reg, &regs) as usize
								}) as Arc<_>;

								println!("INDIRECT REG");
								JumpTrap::Indirect {
									instruction: bytes,
									target,
								}
							},
							capstone_sys::x86_op_type::X86_OP_MEM => {
								/* Jumps with memory operands that use registers
								 * other than RIP are considered indirect jumps. */
								let mem = &op.__bindgen_anon_1.mem;
								let indirect = |reg|
									reg != capstone_sys::x86_reg::X86_REG_INVALID
										&& reg != capstone_sys::x86_reg::X86_REG_RIP;

								if indirect(mem.base) || indirect(mem.index) {
									let target = Arc::new(move |regs| {
										let base = if mem.base != capstone_sys::x86_reg::X86_REG_INVALID {
											sup::cs_reg(mem.base, &regs)
										} else { 0 };
										let index = if mem.base != capstone_sys::x86_reg::X86_REG_INVALID {
											sup::cs_reg(mem.index, &regs)
										} else { 0 };

										((base as i64 + mem.disp) as u64 + index * mem.scale as u64) as usize
									}) as Arc<_>;

									println!("INDIRECT REG+MEM");
									JumpTrap::Indirect {
										instruction: bytes,
										target,
									}
								} else {
									println!("DIRECT");
									JumpTrap::Direct { instruction: bytes }
								}
							},
							capstone_sys::x86_op_type::X86_OP_IMM => {
								/* Jumps with immediates are always direct. */
								println!("DIRECT");
								JumpTrap::Direct { instruction: bytes }
							},
							_ => panic!("invalid Capstone x86 operand type: {flavor}")
						}
					},
					_ => unreachable!()
				};

				assert!(next_trap.replace((address, trap)).is_none());
				false
			}
		)?;
		capstone_sys::cs_free(instruction, 1);

		let (address, trap) = match next_trap {
			Some(value) => value,
			None =>
				/* Not finding a next branch should be next to impossible. Just
				 * assume we did something wrong. */
				panic!("could not find branch instruction")
		};

		/* Write a trap instruction over the jump. */
		sup::vm_write(self.child, address, &[0xcc])?;

		/* Save trap information to be looked up when it gets hit. */
		let _ = self.jump_traps.insert(address as _, trap);

		Ok(())
	}

	pub unsafe fn handle_jump_trap_1(&mut self) -> anyhow::Result<Option<libc::c_ulonglong>> {
		/* The PC will always be one past the trapped address. */
		let pc = sup::pc_of(self.child)? - 1;

		/* Check to see if this is a trap we installed. */
		let mut insn = [0];
		sup::vm_read(self.child, pc as _, &mut insn)?;
		if insn[0] != 0xcc {
			/* This isn't a jump trap. Do nothing. */
			return Ok(None)
		}

		let instruction = match self.jump_traps.get_mut(&pc) {
			Some(JumpTrap::Direct { instruction }) => instruction,
			Some(JumpTrap::Indirect { target, instruction }) => {
				let target = target(sup::regs_of(self.child)?);
				println!("[+] Indirect jump {pc:#x} -> {target:#x}");

				instruction
			},
			None =>
				/* This isn't a jump trap. Do nothing. */
				return Ok(None)
		};

		/* Take the branch. */
		sup::vm_write(self.child, pc as _, instruction)?;
		sup::set_pc_of(self.child, pc)?;
		sup::rptrace!(libc::PTRACE_SINGLESTEP, self.child, sup::nullptr(), sup::nullptr())?;

		Ok(Some(pc))
	}

	pub unsafe fn handle_jump_trap_2(&mut self, restore: libc::c_ulonglong) -> anyhow::Result<()> {
		/* Process the landing block. */
		sup::vm_write(self.child, restore as _, &[0xcc])?;
		self.handle_landing_pad()
	}

	pub unsafe fn handle_stopped(&mut self, status: libc::c_int) -> anyhow::Result<()> {
		let signal = libc::WSTOPSIG(status) & 0x7f;
		let syscall = libc::WSTOPSIG(status) & 0x80 != 0;

		/* Pass this signal through if it's not a trap. */
		if signal != libc::SIGTRAP {
			sup::rptrace!(
				libc::PTRACE_CONT,
				self.child,
				sup::nullptr(),
				libc::WSTOPSIG(status) as libc::uintptr_t)?;
			return Ok(())
		}

		println!("[*] Stopped {status:#x} (Child at {:#x})", sup::pc_of(self.child)?);

		let pid = self.child;
		let cont = move || sup::rptrace!(
			libc::PTRACE_CONT,
			pid,
			sup::nullptr(),
			sup::nullptr());

		self.loop_state = match self.loop_state {
			TrackerLoopState::Setup => {
				/* We have just gained control over the inferior. Set up some
				 * things and continue. */
				println!("[*] Setting up");
				sup::rptrace!(
					libc::PTRACE_SETOPTIONS,
					self.child,
					sup::nullptr(),
					(libc::PTRACE_O_TRACEEXEC
						| libc::PTRACE_O_TRACEEXIT
						| libc::PTRACE_O_TRACESYSGOOD)
					as libc::uintptr_t)?;
				cont()?;

				TrackerLoopState::Idle
			},
			TrackerLoopState::Idle => {
				/* We're not expecting anything specific. Analyze the trap and
				 * react accordingly. */

				let event = status >> 16 & 0xff;
				match event {
					libc::PTRACE_EVENT_EXEC => {
						self.handle_exec_trap()?;
						cont()?;
						TrackerLoopState::Idle
					},
					_ => if let Some(restore) = self.handle_jump_trap_1()? {
						TrackerLoopState::JumpTrapSingleStep(restore)
					} else {
						cont()?;
						TrackerLoopState::Idle
					}
				}
			},
			TrackerLoopState::JumpTrapSingleStep(restore) => {
				self.handle_jump_trap_2(restore)?;
				cont()?;

				TrackerLoopState::Idle
			}
		};

		Ok(())
	}
}

unsafe fn tracker_loop(child: libc::pid_t) -> anyhow::Result<()> {
	let mut tracker = Tracker::new(child)?;

	/* Track the child while it's still alive. */
	let status = loop {
		let mut status = std::mem::zeroed();
		let result = libc::waitpid(child, &mut status as *mut _, libc::__WALL);

		if result == -1 {
			/* Retry interrupted waits. */
			if sup::read_errno() == libc::EINTR { continue }

			/* Child exited unexpectedly. */
			if sup::read_errno() == libc::ECHILD { break None }

			/* We did something wrong. */
			eprint!("waitpid(): ({}) ", sup::read_errno());
			libc::perror(std::ptr::null_mut());

			break None
		}
		debug_assert_eq!(result, child);

		if libc::WIFEXITED(status) {
			/* Child exited normally. */
			break Some(libc::WEXITSTATUS(status))
		} else if libc::WIFSTOPPED(status) {
			/* Handle the stopped status. */
			tracker.handle_stopped(status)?;
		}
	};

	eprintln!("Exited with code {status:?}");
	Ok(())
}

unsafe fn child(progname: *const libc::c_char, argv: *const *const libc::c_char) -> ! {
	/* Request that the tracker trace us. */
	sup::rptrace!(
		libc::PTRACE_TRACEME,
		0,
		sup::nullptr(),
		sup::nullptr()
	).unwrap();

	/* Give the tracer a chance to catch up before the exec(2). */
	libc::raise(libc::SIGTRAP);

	/* Start the child program. */
	let result = libc::execv(progname, argv);
	if result < 0 {
		eprint!("exec(): ({}) ", sup::read_errno());
		libc::perror(std::ptr::null_mut());

		std::process::exit(1)
	}

	/* The exec* family never return unless an error has happened. */
	unreachable!()
}
