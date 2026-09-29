/**
 * JusticeSchool - Login Hook Script v6
 *
 * NO frida-il2cpp-bridge dependency. Uses direct il2cpp C API via NativeFunction.
 *
 * Usage:
 *   frida -H 127.0.0.1:27042 -n Gadget -l research/frida/justice_hook.js
 */

'use strict';

// ---------- Il2Cpp C API bindings ----------

let il2cpp = null;

function initIl2cppApi() {
    const getExp = (name) => {
        try { return Module.getExportByName('libil2cpp.so', name); }
        catch (e) { return null; }
    };
    const domain_get = getExp('il2cpp_domain_get');
    if (!domain_get) return false;
    il2cpp = {
        domain_get: new NativeFunction(domain_get, 'pointer', []),
        thread_attach: new NativeFunction(getExp('il2cpp_thread_attach'), 'pointer', ['pointer']),
        domain_get_assemblies: new NativeFunction(getExp('il2cpp_domain_get_assemblies'), 'pointer', ['pointer', 'pointer']),
        assembly_get_image: new NativeFunction(getExp('il2cpp_assembly_get_image'), 'pointer', ['pointer']),
        image_get_name: new NativeFunction(getExp('il2cpp_image_get_name'), 'pointer', ['pointer']),
        image_get_class_count: new NativeFunction(getExp('il2cpp_image_get_class_count'), 'uint', ['pointer']),
        image_get_class: new NativeFunction(getExp('il2cpp_image_get_class'), 'pointer', ['pointer', 'uint']),
        class_get_name: new NativeFunction(getExp('il2cpp_class_get_name'), 'pointer', ['pointer']),
        class_get_methods: new NativeFunction(getExp('il2cpp_class_get_methods'), 'pointer', ['pointer', 'pointer']),
        method_get_name: new NativeFunction(getExp('il2cpp_method_get_name'), 'pointer', ['pointer']),
        method_get_param_count: new NativeFunction(getExp('il2cpp_method_get_param_count'), 'uint8', ['pointer']),
        method_get_param: new NativeFunction(getExp('il2cpp_method_get_param'), 'pointer', ['pointer', 'uint']),
        method_get_return_type: new NativeFunction(getExp('il2cpp_method_get_return_type'), 'pointer', ['pointer']),
        type_get_name: new NativeFunction(getExp('il2cpp_type_get_name'), 'pointer', ['pointer']),
        free: new NativeFunction(getExp('il2cpp_free') || Module.getExportByName(null, 'free'), 'void', ['pointer']),
    };
    return true;
}

function cstr(ptr) {
    if (ptr.isNull()) return '';
    try { return ptr.readCString(); } catch (e) { return ''; }
}

function typeName(tptr) {
    if (tptr.isNull()) return '?';
    try {
        const p = il2cpp.type_get_name(tptr);
        const s = cstr(p);
        // il2cpp_type_get_name allocates; free it (best effort)
        try { il2cpp.free(p); } catch (e) {}
        return s;
    } catch (e) { return '?'; }
}

// ---------- string / dict readers ----------

function readIl2cppString(ptr) {
    if (ptr.isNull()) return '(null)';
    try {
        const length = ptr.add(16).readU32();
        if (length > 10000) return `(invalid string, length=${length})`;
        return ptr.add(20).readUtf16String(length);
    } catch (e) {
        return `<unreadable:${e.message}>`;
    }
}

function trunc(s, maxLen = 500) {
    if (s === null || s === undefined) return '(null)';
    s = String(s);
    return s.length > maxLen ? s.substring(0, maxLen) + `...[${s.length} chars]` : s;
}

// Dictionary<string,string> raw walk.
// _entries at +24 (from v4 debug), Entry = hash(4)+next(4)+key(8)+value(8) = 24B.
// Il2Cpp SZARRAY data starts at +32.
function dumpDictionary(dictPtr) {
    if (dictPtr.isNull()) return '(null dict)';
    try {
        const out = {};
        const entriesArr = dictPtr.add(24).readPointer();
        if (entriesArr.isNull()) return '(entries null)';
        const count = dictPtr.add(32).readU32();
        if (count > 1000) return `(suspicious count=${count})`;
        const dataStart = entriesArr.add(32);
        for (let i = 0; i < count; i++) {
            const e = dataStart.add(i * 24);
            if (e.readS32() < 0) continue;
            const k = readIl2cppString(e.add(8).readPointer());
            const v = readIl2cppString(e.add(16).readPointer());
            out[k] = v;
        }
        return JSON.stringify(out, null, 1);
    } catch (e) {
        return `(dict dump failed: ${e.message})`;
    }
}

// ---------- method lookup ----------

function findMethods(className, methodName, paramCount) {
    const results = [];
    const domain = il2cpp.domain_get();
    il2cpp.thread_attach(domain);
    const sizePtr = Memory.alloc(8);
    const assemblies = il2cpp.domain_get_assemblies(domain, sizePtr);
    const nAsm = sizePtr.readU64();
    for (let i = 0; i < nAsm; i++) {
        const asm = assemblies.add(i * 8).readPointer();
        const img = il2cpp.assembly_get_image(asm);
        const imgName = cstr(il2cpp.image_get_name(img));
        if (imgName !== 'Assembly-CSharp') continue;
        const nCls = il2cpp.image_get_class_count(img);
        for (let c = 0; c < nCls; c++) {
            const klass = il2cpp.image_get_class(img, c);
            if (cstr(il2cpp.class_get_name(klass)) !== className) continue;
            const iter = Memory.alloc(8); iter.writeU64(0);
            while (true) {
                const method = il2cpp.class_get_methods(klass, iter);
                if (method.isNull()) break;
                const mName = cstr(il2cpp.method_get_name(method));
                if (mName !== methodName) continue;
                const pc = il2cpp.method_get_param_count(method);
                if (pc !== paramCount) continue;
                // MethodInfo.methodPointer is at offset 0
                const fnPtr = method.readPointer();
                const sig = [];
                for (let p = 0; p < pc; p++)
                    sig.push(typeName(il2cpp.method_get_param(method, p)));
                const ret = typeName(il2cpp.method_get_return_type(method));
                results.push({ addr: fnPtr, sig: sig.join(', '), ret });
            }
        }
    }
    return results;
}

// ---------- main ----------

function waitForIl2cpp() {
    return new Promise((resolve) => {
        const t = setInterval(() => {
            try {
                Module.getExportByName('libil2cpp.so', 'il2cpp_thread_attach');
                clearInterval(t); resolve();
            } catch (e) {}
        }, 500);
    });
}

async function main() {
    console.log('[*] justice_hook v6 starting...');
    await waitForIl2cpp();
    const mod = Process.enumerateModules().filter(m => m.name === 'libil2cpp.so')[0];
    if (mod) console.log(`[*] libil2cpp.so base @ ${mod.base}`);
    if (!initIl2cppApi()) { console.log('[!] il2cpp exports not found'); return; }
    console.log('[*] IL2CPP API bound. Waiting for Assembly-CSharp...');

    // wait until Assembly-CSharp appears
    let ready = false;
    for (let i = 0; i < 120; i++) {
        try {
            const domain = il2cpp.domain_get();
            const sp = Memory.alloc(8);
            const asms = il2cpp.domain_get_assemblies(domain, sp);
            const n = sp.readU64();
            for (let k = 0; k < n; k++) {
                const img = il2cpp.assembly_get_image(asms.add(k * 8).readPointer());
                if (cstr(il2cpp.image_get_name(img)) === 'Assembly-CSharp') { ready = true; break; }
            }
            if (ready) break;
        } catch (e) {}
        await new Promise(r => setTimeout(r, 1000));
    }
    if (!ready) { console.log('[!] Assembly-CSharp never loaded'); return; }
    console.log('[*] Assembly-CSharp found. Installing hooks...');

    const CN = 'ProtocolGame_HttpRequest';
    let n = 0;
    const hook = (mName, pc, onEnter, onLeave) => {
        const ms = findMethods(CN, mName, pc);
        if (!ms.length) { console.log(`[!] Not found: ${mName} (${pc})`); return; }
        for (const m of ms)
            console.log(`[?] ${CN}.${mName}(${m.sig}) -> ${m.ret} @ ${m.addr}`);
        const m = ms[0];
        console.log(`[+] Hooking ${mName} @ ${m.addr}`);
        Interceptor.attach(m.addr, { onEnter, onLeave });
        n++;
    };

    hook('V4_POST_Login', 3,
        function (args) {
            console.log('\n========== V4_POST_Login ==========');
            console.log(`  app_key: ${trunc(readIl2cppString(args[0]))}`);
            console.log(`  content: ${trunc(readIl2cppString(args[1]))}`);
            console.log(`  apiName: ${trunc(readIl2cppString(args[2]))}`);
        },
        function () { console.log('====================================\n'); });

    hook('Sign', 2,
        function (args) {
            console.log('\n---------- Sign called ----------');
            this.c = readIl2cppString(args[0]);
            this.d = dumpDictionary(args[1]);
            console.log(`  content: ${trunc(this.c)}`);
            console.log(`  dict: ${this.d}`);
        },
        function (retval) {
            let out;
            try {
                const s = readIl2cppString(retval);
                out = s.startsWith('(invalid')
                    ? `(RAW_PTR=${retval} qword0=${retval.readU64().toString(16)})`
                    : s;
            } catch (e) { out = `(read failed: ${e.message})`; }
            console.log(`  => SIGN OUTPUT: ${trunc(out, 300)}`);
            console.log('----------------------------------');
            console.log(`[SIGN_DATA] content=${JSON.stringify(trunc(this.c, 2000))} dict=${this.d} output=${JSON.stringify(trunc(out, 500))}\n`);
        });

    hook('GetDefaultParams', 0,
        function () { console.log('\n---------- GetDefaultParams ----------'); },
        function (retval) {
            console.log(`  [return] ${dumpDictionary(retval)}`);
            console.log('----------------------------------\n');
        });

    hook('V3_POST_AllInOne', 1,
        function (args) {
            console.log('\n========== V3_POST_AllInOne ==========');
            console.log(`  app_key: ${trunc(readIl2cppString(args[0]))}`);
            console.log('====================================\n');
        }, null);

    console.log(`\n[*] ${n} hooks installed. Trigger login. Look for [SIGN_DATA].\n`);
}

main();
