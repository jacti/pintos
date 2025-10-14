#ifndef VM_TYPE_H
#define VM_TYPE_H

enum vm_type {
    /* page not initialized */
    VM_UNINIT = 0,
    /* page not related to the file, aka anonymous page */
    VM_ANON = 1,
    /* page that realated to the file */
    VM_FILE = 2,
    /* page that hold the page cache, for project 4 */
    VM_PAGE_CACHE = 3,

    /* Bit flags to store state */

    /* Auxillary bit flag marker for store information. You can add more
     * markers, until the value is fit in the int. */
    VM_MARKER_0 = (1 << 3),
    VM_MARKER_1 = (1 << 4),

    /* DO NOT EXCEED THIS VALUE. */
    VM_MARKER_END = (1 << 31),
};

#endif 