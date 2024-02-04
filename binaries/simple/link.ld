PHDRS
{
	/* Load just two sections, one RX and the other R, 512MBs apart, with the
	 * first one located just past the first 4GB. */
	TEXT   PT_LOAD AT(4096M) FLAGS(5);
	RODATA PT_LOAD AT(4608M) FLAGS(4);
}

SECTIONS
{
	/* Place the .text and .rodata* sections into the TEXT and RODATA segments. */
	.text   4096M : { *(.text*)   } : TEXT
	.rodata 4608M : { *(.rodata*) } : RODATA

	/* Our entry point is the `entry` symbol in `main.s`. */
	ENTRY(entry)
}
