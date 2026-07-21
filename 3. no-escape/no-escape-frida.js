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
