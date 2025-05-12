ENTRY(_hw3_unicorn)

EXTERN(purple)
EXTERN(white)

PHDRS
{
	data PT_LOAD FLAGS ( 6 ) ;
	text PT_LOAD FLAGS ( 3 ) ;
	rodata PT_LOAD FLAGS ( 5 ) ;
}

SECTIONS
{
  . = 0x60000;
  .data : 
  {
	*(.data)
	*(.bss)
  } :data 

  . = 0x400000;
  .text : 
  {
	
	*(.text)
  } :text 

  . = 0x80000000;
  .rodata : 
  {
	
	*(.rodata)
  } :rodata 

}

