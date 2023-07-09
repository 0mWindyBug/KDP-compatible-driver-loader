# KDP Compatible Unsigned Driver Loader 
Kernel Unsigned Driver Loader ,  KDP compatible,  Leveraging gdrv.sys's Write Primitive 

Tested on Windows 10 21H2 and 22H2

# Usage:
**load target driver-> Loader.exe gdrv.sys driver.sys**

**unload target driver -> Loader.exe  driver.sys**

# How it works 
Driver Signature Enforcement is implemented within CI.dll. Based on Reverse Engineering of the signature validation process we know nt!SeValidateImageHeader calls CI!CiValidateImageHeader.  
the return status from CiValidateImageHeader determines whether the signature is valid or not.   
Based on Reverse Engineering of nt!SeValidateImageHeader we understand it uses an array -  SeCiCallbacks to retrieve the address of CiValidateImageHeader before calling it.  
SeCiCallbacks is initialized by CiInitialize.  to be precise,  a pointer to nt!SeCiCallbacks is passed to CiInitialize as an argument allowing us to map ntoskrnl.exe to usermode and perform the following:   
sig scan for the lea instruction prior to the CiIntialize call.  
calculate  the address of SeCiCallbacks in usermode  
calculate the offset from the base of ntoskrnl in usermode  
add the same offset to the base of ntoskrnl.exe in kernelmode.  
once we have the address of SeCiCallbacks in kernel, all we need to do is to add a static offset to CiValidateImageHeader's entry in the array.  
leverage the write primitive to replace the address of CiValidateImageHeader with the address of ZwFlushInstructionCache, or any function that will always return NTSTATUS SUCCESS with the same prototype of CiValidateImageHeader. 
***************************
# Demo
![251973627-171334ef-28b7-42c9-8f59-daa647c9603d](https://github.com/0mWindyBug/KDP-Compatible-Unsigned-Driver-Loader/assets/139051196/a591d9ba-d028-4591-8440-c67d9d7818da)

  
# Notes
whilst the implemented technique does not require a read primitive , we do use the read primitive to restore the original CiValidateImageHeader after the unsigned driver is loaded.   
you can modify the code to not use the read primitive and it will work just fine since  SeCiCallbacks is not PatchGuard protected  
built on top of the core  of gdrv-loader 
