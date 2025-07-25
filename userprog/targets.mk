userprog_SRC  = userprog/process.c	# Process loading.
userprog_SRC += userprog/exception.c	# User exception handler.
userprog_SRC += userprog/syscall-entry.S # System call entry.
userprog_SRC += userprog/syscall.c	# System call handler.
userprog_SRC += userprog/gdt.c		# GDT initialization.
userprog_SRC += userprog/tss.c		# TSS management.
userprog_SRC += userprog/file_abstract.c	# FILE absraction
userprog_SRC += userprog/check_perm.c		# check_permission
