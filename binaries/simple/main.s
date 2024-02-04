.section .text
	.global entry
entry:
	# Call `target` indirectly.
	movabs $target, %rax
	callq *%rax

	# syscall: exit(0)
	movq $60, %rax
	movq $0, %rdi
	syscall

	# Catch ourselves before we do anything wrong.
halt:
	jmp halt

.section .text.target
target:
	# syscall: write(stdout, hello, 14)
	movq $1, %rax
	movq $1, %rdi
	leaq hello(%rip), %rsi
	movq $14, %rdx
	syscall

	ret

.section .rodata
hello: .asciz "Hello, World!\n"
