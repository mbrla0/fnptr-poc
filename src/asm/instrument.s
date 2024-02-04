.include "defs.inc"

; The instrumentation helper gadget.
;
; The code in this section is responsible for checking whether the target of
; a given indirect jump has alread been instrumented by the debugger, by doing a
; binary search through the list of known jump targets. That list is owned and
; controlled by the debugger, but resides in the memory space of the inferior.
; 
; Since usually these jumps will only have a handful of distinct targets
; throughout their limetimes, doing this allows us to save quite a bit of time,
; by avoid the costly rendezvous with the debugger in the hit case, and only
; adding a comparatively small overhead to the miss case.
;
; Additionally, it only makes sense to use this gadget for indirect jumps that
; are hit multiple times. The fewer times an indirect jump instruction is used,
; the more likely it is for the ratio of hits to misses to be lower.
;

.code64
.section InstrumentationHelper
	pushq %rax
	pushq %r15
	pushq %r14
	pushq %rbx
	
	; Load long-lived parameters
	;
	; %rbx => Target jump address
	; %r15 => Base address of cache
	; %r14 => Number of elements in cache
	call getTargetAddress(%rip)
	movq %rax, %rbx
	movq cache(%rip), %r15
	movq cacheLen(%rip), %r14

	; Check if we've already seen this addres.
	xorq %rax, %rax


	; This is a new target address. Defer to the debugger.
	int3


	popq %rbx
	popq %r14
	popq %r15
	popq %rax

.section InstrumentationHelperParamsLocal
cache:
	; The address of the cache region used by this instrument.
	.quad 0
cacheLen:
	; The number of addresses in the cache region.
	.quad 0
getTargetAddress:
	; The gadget that loads the effective address of the jump
	; target into %rax and calls `ret`.
	; 
	; As an example, this assumes the address is stored in %rdx
	movq %rdx, %rax
	ret

