This application is a jailbreak-detection CTF.

I begin with Ghidra and identify the following functions that contain "jailbreak" in their name.

![[ghidra-symbol-jailbreak.png]]

The logic flow looks like this. I renamed a few of the variables for readability.

```C
bool _$s9No_Escape12isJailbroken(ulong param_1)

{
  uint isJailbroken;
  uint local_18;
  uint local_14;
  
  _$s9No_Escape22checkForJailbreakFiles33();
  local_14 = (uint)param_1;
  if ((param_1 & 1) == 0) {
    _$s9No_Escape33checkForWritableSystemDirectories33();
  }
  else {
    local_14 = 1;
  }
  if ((local_14 & 1) == 0) {
    _$s9No_Escape12canOpenCydia33();
    local_18 = local_14;
  }
  else {
    local_18 = 1;
  }
  if ((local_18 & 1) == 0) {
    _$s9No_Escape21checkSandboxViolation33();
    isJailbroken = local_18;
  }
  else {
    isJailbroken = 1;
  }
  return (isJailbroken & 1) != 0;
}
```

The function `isJailbroken` essentially has four different checks to see if the device is jailbroken. 

First, it checks for any files that a jailbroken device would have, e.g., Cydia, `/Application/cydia.app`, `/bin/sshd`, etc. 

I am using palera1n with Sileo, so I don't think I will flag for Cydia, but I may flag for some 'illegal' binaries. 

The next check is to see if the system directory is writable, as this would indicate a jailbreak. 

It then uses a deep link of `cydia://` to attempt to open Cydia, in case it has been renamed, as a further check. 

The final check is a sandbox violation check.

Fortunately, we can use Frida to make this function always return false. Fun hack — our `.js` Frida script looks like this: 

```js
console.log("Objc Check Script loaded, PID:", Process.id);

const name = "_$s9No_Escape12isJailbrokenSbyF";

const m = Process.mainModule;
const hit = m.enumerateSymbols().find(
        s => s.name === name || s.name === name.replace(/^_/, "") // This replace just makes sure we can hit with and without the leading underscore. 
    );



Interceptor.attach(hit.address, {
                onLeave(retval) {
                        retval.replace(ptr(0));
                }
});
```

This will give you the flag `MHL{hidin9_in_pl@in_5i9h+}`