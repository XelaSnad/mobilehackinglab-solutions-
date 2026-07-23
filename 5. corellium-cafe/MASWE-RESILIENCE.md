## MASWE-0097: Root/Jailbreak Detection Not Implemented

Jailbreak detection can be seen in Ghidra. With strings such as `/Application/Cydia.app` being in the binary. Additionally in the `Info.plist`, we see that cydia is declared as a method for url deeplinking. Which means it most likely attempts to use a url deeplink aswell as the function `::fileUrlWithPath` to see if that specific Cydia file exists.

One can simply use objection, which will automaticaly hook methods such as `fileUrlWithPath` and make them return `False` when it searches for the file `/Application/Cydia.app`. On git hub I took the Objection agent's code and edited a little bit to give a demonstration of this concept. 

```javascript
Interceptor.attach(
  ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
    onEnter(args) {
      this.is_common_path = false;
      this.path = new ObjC.Object(args[2]).toString();
      if (this.path === "/Applications/Cydia.app") {
        console.log("hit")
        this.is_common_path = true;
      }
    },
    onLeave(retval) {
      if (!this.is_common_path) return;
      if (!retval.isNull()) return;  // already YES, nothing to do

      send(`[${ident}] fileExistsAtPath: check for ${this.path} ` +
           `returned NO, forcing YES.`);
      retval.replace(ptr(0x1));
    },
  }
);
```

![[jailbreak.png]]

