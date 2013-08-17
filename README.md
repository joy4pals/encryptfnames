In order to implement the address space operations as part of the homework, the following files were added/modified:
Files Added:
-----------
hw3/set_key_ioctl.c:
-------------------
	This is a user level utility to set the key for our encryption filesystem. It should be called as 
./set_key_ioctl -k encryption_key /mount_point_wrapfs

hw3/sparse.c:
------------
	This is a user end c utility that creates a sparse file with contents:
hello<holes>world. This should be invoked as:
./sparse

fs/wrapfs/mount_wrapfs.sh:
--------------------------
	This utility script insmods wrapfs and  mounts the ext3 at mount point /n/scratch and then it mounts wrapfs on top of ext3 at /tmp. While mounting wrapfs it supplies some mount time options such as debug=#(extra credit part) and mmap (swich to toggle between address_space operations and vm operations). In case the changes needs to be made to the mount options, they need to be made here.The debug options are discussed in the extra credit part.

fs/wrapfs/umount_wrapfs.sh:
--------------------------
	This utility unmounts the wrapfs and then the ext3 and then rmmods the wrapfs.

fs/wrapfs/umount_wrapfs_only.sh
------------------------------
	This utility just unmounts wrapfs and not the underlying ext3.

fs/wrapfs/mount_wrapfs_only.sh
-------------------------------
	This utility just mounts wrapfs at /tmp on top ext3 which it assumes mounted on /n/scratch.

Files Modified:
---------------
fs/wrpafs/main.c: 
----------------
	included the mount options to enable/ disable the address space operation based on the mount time flag mmap. This also contains the implementation of the the extra credit part concerning the debug options.

fs/wrpafs/mmap.c: 
----------------
	The file contains the actual address space operation of the readpage, writepage, write_begin, and write_end. The functions are taken from the corresponding implementation from the ecryptfs' implementation of the address-space  operation. 

fs/wrpafs/file.c: 
----------------
	This file contains the implementation of the ioctl that sets the key passed to it in the wrpafs_superblock info. The actual user level call to the ioctl is mentioned below.

IOCTL TO SET KEY
-----------------
./call_ioctl -k <key> <mount point>

A possible call to this can be (assuming the fact that the wraps is mounted at the /tmp and the encryption key we want to pass is hello_world):
./call_ioctl -k hello_world /tmp

Other than this I have also written the two scripts that would help the mounting and unmounting of the filesystems on the drive /dev/sdb1

mount_wrapfs.sh:
This script installs the ext3 on /n/scratch and wrapfs at /tmp
in order to specify the different mount point options we need to change the line 10 of the script which says:
mount -t wrapfs -o debug=32,mmap $LOWER_MNTPT $UPPER_MNTPT

the value of the debug specifies the which files you want to print the debug messages for:1: enable debugging for superblock ops
2: enable debugging for inode ops
4: enable debugging for dentry ops
16: enable debugging for file ops
32: enable debugging for address_space ops
64: enable debugging for all other ops
or any combination of them
The option mmap specifies the option whether the address_space operations should be used or the default vm_ops should be used.
In case the flag is passed as it is the case above, the address_space options are enabled.

NOTE:
-----

In the vanilla state only the address space operations work and nothing else.
In order to turn on the encryption feature the compile time flag WRAPFS_CRYPTO must be turned on and similarly to check the extra credit part the flag EXTRA_CREDIT must be turned on.

In case the WRAPFS_CRYPTO is enabled, please set the encryption key using the set_key_ioctl utility in the hw3/ folder. In case you forget to do so, the system will throw an Operation not permotted error. 

How it all works (A demo):
____________________
mount the wrpafs on top of ext3 (change the mount time options as desired in the file fs/wrapfs/mount_wrapfs.sh). The following examples assumes that ext3 is mounted at /n/scratch and the wrapfs is mounted at /tmp.
#     : commands
>>    : output

case 1:
-------
	Only address space operations are enabled. As no encryption therefore, the same text gets printed in the underlying file system.
#./mount_wrapfs.sh
#echo "hello world" >> /tmp/test.txt
#cat /tmp/test.txt
>>hello world
#cat /n/scratch/test.txt
>>hello world

case 2: 
-------
Now address_space options along with WRAPFS_CRYPTO is enabled.

echo "hello world" >> /tmp/test.txt
>>-bash: echo: write error: Operation not permitted

This is because the key is not set. Now set the key and try again:
#./set_key_ioctl -k jellybean /tmp
#echo "hello world" >> /tmp/test.txt
#cat /tmp/test.txt 
>>hello world
#cat /n/scratch/test.txt 
>>8B?w????;Cd?

Now in order to check the decryption, we do this:
unmount using unmount_wrapfs_only. Now we should not see the file test.txt under /tmp. remount wrapfs using the mount_wrapfs_only and then set the key(should be same as the previous). cat the contents of the file /tmp/test.txt

#./umount_wrapfs_only.sh
>>ONLY Wrapfs will now be un-mounted
>>Wrapfs unmounted successfully.!!

#./mount_wrapfs_only.sh
>>This script will now mount wrapfs ONLY and not ext3
>>This assumes wrapfs in already insmoded
>>file systems mounted successfully..
#./set_key_ioctl -k jellybean /tmp
#cat /tmp/test.txt 
>>hello world

case 3:
------
create a sparse file. This is done using the utility hw3/sparse
#./sparse 
#cat /tmp/sparse.txt 
>>helloworld
#cat /n/scratch/sparse.txt 
>>8B?w????I/?#???]???ih??G
                        ??L???}$??l??9Bl?3Ĭߕg?Ż?}?&G
#./umount_wrapfs_only.sh
>>ONLY Wrapfs will now be un-mounted
>>Wrapfs unmounted successfully.!!
#./mount_wrapfs_only.sh
>>This script will now mount wrapfs ONLY and not ext3
>>This assumes wrapfs in already insmoded
>>file systems mounted successfully..
#./set_key_ioctl -k jellybean /tmp
#cat /tmp/sparse.txt 
>>helloworld


Design principles and caveats
_____________________________

A>
Setting the encryption key :-
The system encrypts the contents of the file using AES in CRT mode. ion order to create a 32 byte key the key passed by the user is hashed using md5 checksum and then that is passed as the key to the encryption algorithm.

B>
When a user tries to write something to a file and next time he appends
something else to the same file, the problem that did occur was that the lower
fs wrote the entire thing to the end of the file. Lets say a user executes the
following commands:
echo "hello" > /tmp/test.txt
echo "world!!" >> /tmp/test.txt
Then the content of the file in wrapfs is:
hello
world!!
But the content of the file in hte lower fs is something like:
hello
hello
world!!
This occurs because inside the call to the vfs_write of the page, the kernel
call the function ->generic_write_checks, this function has a line:
/* FIXME: this is for backwards compatibility with 2.4 */
	if (file->f_flags & O_APPEND)
        	*pos = i_size_read(inode);
This says if the O_APPEND flag is set then do not respect the position
argument of vfs_write and write everything to the end of the file. IN order 
to over come this problem the  work around that is done here is:
If the append flag is set, unset it and then call vfs_write. This rectifies
the error and we correctly get the desired content in the lower file which
reads as:
hello
world!!

C>Sparse file handing
The case of the	sparse file is handled.	A large	part of	this is	taken from the
ecryptfs implementation.


EXTRA CREDIT
-------------
The extra credit question regarding the debug options is done. In order to
incorporate the debug message corresponding to the return of a function, a new
debug message similar to UDBG is added in wrapfs.h. This macro(DBGRET) takes an
integer argument and prints it in the syslog. Debug messages are stuck in the m
ajor files at the start	and just before the return of the functions.

The debug option is enabled by turning on the EXTRA_CREDIT flag and then mounti
ng wrapfs with the mount time flags "-O debug=##". This number determines the which of the debug options will be turned on.
2: enable debugging for inode ops
4: enable debugging for dentry ops
16: enable debugging for file ops
32: enable debugging for address_space ops
64: enable debugging for all other ops
or any combination of them. Therefore inorder to turn on hte debug option for address_space and file we need to specify something like debug=48.
