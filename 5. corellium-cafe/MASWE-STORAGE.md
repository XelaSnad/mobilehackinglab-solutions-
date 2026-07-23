## MASWE-0001: Insertion of Sensitive Data into Logs

Using ghidra we found the string `CorelliumizAwesome` , it is specifically used in

`    os::$os_log("CorelliumizAwesome",0x12,2,0x100000000,pOVar3,pOVar4, PTR___swiftEmptyArrayStorage_1006ca400);` 

We see it being leaked to the OS log. 

![[promocode.png]]

Interesting note here, that on a non-virutalised device, when you try to input the code it pulls up a numpad so this vulnerability can only be exploited with a keyboard attached to the device or if you use other methods. 

![[promocode_empty.png]]

## MASWE-0006: Sensitive Data Stored Unencrypted in Private Storage Locations

### Credit Card Number stored in plain-text

Simply going to the private data of the application we can see that a order locally stores the credit card number in the database `/var/mobile/Containers/Data/Application/{ID}/Library/Application Support/OrderModel.sqlite`

The table `ZCUSTOMERINFO`  contains the following collumns 

| Z_PK | Z_ENT | Z_OPT | ZCCNumber | ZFIIRSTNAME | ZUUID |
| ---- | ----- | ----- | --------- | ----------- | ----- |
Containing the credit card number in plaintext.

### Debug credentials in the application


The first clue we were given that there is some credentials in the application, we will use, ghidra and start searching strings for the `@` sign for a valid email address. 

This techinque found the string `coreadmin@corellium.com`, now we need to find a password. 

Investigating the private data we find in Preferences, a valid login and password 

```
\h:\w \u$ cat Library/Preferences/com.corellium.Cafe.plist                                                          UserNameXPassword coreadmin@corellium.com iLoveCoffee1234

```

