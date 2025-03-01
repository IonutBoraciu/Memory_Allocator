# Memory Allocator Simulating using linked lists

### Description:

   After the arena has been allocated, when a block is allocated, the following checks are performed:
   	* If a block has already been allocated in such a way that the new block continues the virtual memory of the existing one, a new miniblock is added to the already existing block.
    	* If the first condition is not met, a new block is added in order.
     	* Finally, a check is performed to determine if adjacent blocks should be concatenated.
  In the deallocation function, the position of the miniblock is located, and then the corresponding miniblock is freed. If it is the last miniblock in the list, the entire block is also freed. If it is in the middle of the list, the block is split into two separate blocks.

  The MPROTECT function changes the access permissions of the data stored in virtual memory zones, preventing them from being accessed, read, etc.

  The WRITE function locates the position from which writing should begin. If the data fits within the current miniblock, it writes everything there. Otherwise, it continues into the following miniblocks, if they exist. If the data to be written is too large, it writes as much as possible within the block.

  The READ function reads (if permission allows) the data stored at the specified memory address.

  The PMAP function prints information about the arena and the access permissions of the allocated memory regions.

  The DEALLOC function frees all program resources and stops execution.

Through this project, I have improved my ability to identify and fix memory leaks. Additionally, I gained a better understanding of how doubly linked lists work and became more familiar with void* data types and the necessary type casting for their use.
