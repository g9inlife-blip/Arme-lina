/**
 * JusticeSchool (com.Alioth.JusticeSchool.cn) - Login Hook Script v4
 *
 * NO frida-il2cpp-bridge, NO frida-compile needed.
 * Resolves IL2CPP exports by parsing /proc/self/maps + ELF directly,
 * because Frida's module enumeration misses Houdini-translated ARM libs
 * on x86_64 emulators.
 *
 * Hooks:
 *  - ProtocolGame_HttpRequest.V4_POST_Login(app_key, content, apiName)
 *  - ProtocolGame_HttpRequest.Sign(content, apiName)
 *  - ProtocolGame_HttpRequest.GetDefaultParams()
 *  - ProtocolGame_HttpRequest.V3_POST_AllInOne(app_key)
 *
 * Usage:
 *   frida -U -p <PID> -l justice_hook.js
 *   (attach AFTER the game has loaded the Unity engine)
 *
 * Output: [SIGN_DATA] lines carry Sign input/output pairs for
 *         reverse-engineering the signature algorithm.
 */

'use strict';

// Parameter names (from static analysis, NEWVERSION-003)
const PARAMS = {
    'V4_POST_Login': ['app_key', 'content', 'apiName'],
    'Sign': ['content', 'apiName'],
    'GetDefaultParams': [],
    'V3_POST_AllInOne': ['app_key'],
};
const CLASS_NAME = 'ProtocolGame_HttpRequest';
const LIB_NAME = 'libil2cpp.so';

// ---------- helpers ----------

function readIl2cppString(ptr) {
    if (ptr.isNull()) return '(null)';
    try {
        // Il2CppString (64-bit): [klass(8)][monitor(8)][length(4)][chars...]
        const length = ptr.add(16).readU32();
        if (length > 10000) return `(string too long: ${length} chars)`;
        return ptr.add(20).readUtf16String(length);
    } catch (e) {
        return `<unreadable:${e.message}>`;
    }
}

function trunc(s, maxLen) {
    maxLen = maxLen || 500;
    if (s === null || s === undefined) return '(null)';
    s = String(s);
    if (s.length > maxLen) {
        return s.substring(0, maxLen) + `...[truncated ${s.length} chars total]`;
    }
    return s;
}

// ---------- ELF-based export resolution ----------
// Finds the module base via /proc/self/maps and resolves dynamic
// symbols by parsing the ELF file directly.

function findModuleBase(libFileName) {
    const maps = File.readAllText('/proc/self/maps');
    for (const line of maps.split('\n')) {
        if (line.indexOf(libFileName) === -1) continue;
        // format: addr_start-addr_end perms offset dev inode pathname
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;
        const range = parts[0].split('-');
        const offset = parts[2];
        if (offset === '00000000' && parts[1].indexOf('r') === 0) {
            return { base: ptr('0x' + range[0]), path: parts[5] };
        }
    }
    return null;
}

function resolveElfExport(modulePath, baseAddr, symbolName) {
    const buf = File.readAllBytes(modulePath);
    const dv = new DataView(buf);
    const u8 = new Uint8Array(buf);

    function u16(off) { return dv.getUint16(off, true); }
    function u32(off) { return dv.getUint32(off, true); }
    function u64(off) { return Number(dv.getBigUint64(off, true)); }

    // ELF header
    if (u32(0) !== 0x464C457F) throw new Error('not an ELF file');
    const e_phoff = u64(0x20);
    const e_phnum = u16(0x38);

    // Collect PT_LOAD segments for vaddr -> file offset translation,
    // and locate PT_DYNAMIC.
    const loads = [];
    let dynOff = -1, dynSize = 0;
    for (let i = 0; i < e_phnum; i++) {
        const ph = e_phoff + i * 56;
        const p_type = u32(ph);
        const p_offset = u64(ph + 8);
        const p_vaddr = u64(ph + 16);
        const p_filesz = u64(ph + 32);
        if (p_type === 1) { // PT_LOAD
            loads.push({ vaddr: p_vaddr, offset: p_offset, filesz: p_filesz });
        } else if (p_type === 2) { // PT_DYNAMIC
            dynOff = p_offset;
            dynSize = p_filesz;
        }
    }
    if (dynOff < 0) throw new Error('no PT_DYNAMIC');

    function vaddrToOffset(vaddr) {
        for (const s of loads) {
            if (vaddr >= s.vaddr && vaddr < s.vaddr + s.filesz) {
                return s.offset + (vaddr - s.vaddr);
            }
        }
        return -1;
    }

    // Parse dynamic entries
    let symtabV = 0, strtabV = 0, strsz = 0, syment = 24;
    for (let off = dynOff; off < dynOff + dynSize; off += 16) {
        const tag = dv.getBigInt64(off, true);
        const val = u64(off + 8);
        if (tag === 6n) symtabV = val;          // DT_SYMTAB
        else if (tag === 5n) strtabV = val;     // DT_STRTAB
        else if (tag === 10n) strsz = val;      // DT_STRSZ
        else if (tag === 11n) syment = val;     // DT_SYMENT
        else if (tag === 0n) break;             // DT_NULL
    }
    if (!symtabV || !strtabV || !strsz) throw new Error('missing dynamic info');

    const symtabOff = vaddrToOffset(symtabV);
    const strtabOff = vaddrToOffset(strtabV);
    if (symtabOff < 0 || strtabOff < 0) throw new Error('vaddr translation failed');

    function readCString(off) {
        let end = off;
        while (end < u8.length && u8[end] !== 0) end++;
        let s = '';
        for (let i = off; i < end; i++) s += String.fromCharCode(u8[i]);
        return s;
    }

    // Linear scan of dynamic symbols
    const maxSyms = 200000;
    for (let i = 0; i < maxSyms; i++) {
        const so = symtabOff + i * syment;
        if (so + 24 > u8.length) break;
        const st_name = u32(so);
        const st_value = u64(so + 8);
        if (st_name === 0 || st_value === 0) continue;
        if (st_name >= strsz) continue;
        const name = readCString(strtabOff + st_name);
        if (name === symbolName) {
            return baseAddr.add(st_value);
        }
        // Heuristic stop: after the null-heavy tail begins we keep going a bit
        if (i > 0 && st_name === 0 && st_value === 0 && i > 50000) break;
    }
    return ptr(0);
}

// ---------- raw IL2CPP API (no bridge) ----------

let api = null;
let il2cppBase = null;

function initApi() {
    const mod = findModuleBase(LIB_NAME);
    if (!mod) throw new Error(LIB_NAME + ' not found in /proc/self/maps');
    il2cppBase = mod.base;
    console.log(`[*] ${LIB_NAME} base @ ${il2cppBase} (${mod.path})`);

    const exp = (n) => {
        const addr = resolveElfExport(mod.path, mod.base, n);
        if (addr.isNull()) throw new Error('export not found: ' + n);
        return addr;
    };
    api = {
        domain_get: new NativeFunction(exp('il2cpp_domain_get'), 'pointer', []),
        domain_get_assemblies: new NativeFunction(exp('il2cpp_domain_get_assemblies'), 'pointer', ['pointer', 'pointer']),
        assembly_get_image: new NativeFunction(exp('il2cpp_assembly_get_image'), 'pointer', ['pointer']),
        image_get_name: new NativeFunction(exp('il2cpp_image_get_name'), 'pointer', ['pointer']),
        class_from_name: new NativeFunction(exp('il2cpp_class_from_name'), 'pointer', ['pointer', 'pointer', 'pointer']),
        class_get_methods: new NativeFunction(exp('il2cpp_class_get_methods'), 'pointer', ['pointer', 'pointer']),
        method_get_name: new NativeFunction(exp('il2cpp_method_get_name'), 'pointer', ['pointer']),
        method_get_param_count: new NativeFunction(exp('il2cpp_method_get_param_count'), 'uint32', ['pointer']),
    };
}

// methodPointer is the first field of MethodInfo (offset 0) on Unity 2019-2022 IL2CPP.
function findMethodImpl(className, methodName, paramCount) {
    const domain = api.domain_get();
    const countPtr = Memory.alloc(Process.pointerSize);
    const assemblies = api.domain_get_assemblies(domain, countPtr);
    const count = countPtr.readU32();

    let image = ptr(0);
    const emptyNs = Memory.allocUtf8String('');
    for (let i = 0; i < count; i++) {
        const asm = assemblies.add(i * Process.pointerSize).readPointer();
        const img = api.assembly_get_image(asm);
        const name = api.image_get_name(img).readCString();
        if (name === 'Assembly-CSharp' || name === 'Assembly-CSharp.dll') { image = img; break; }
    }
    if (image.isNull()) {
        console.log('[!] Assembly-CSharp not found');
        return ptr(0);
    }

    const klass = api.class_from_name(image, emptyNs, Memory.allocUtf8String(className));
    if (klass.isNull()) {
        console.log(`[!] Class not found: ${className}`);
        return ptr(0);
    }

    const iter = Memory.alloc(Process.pointerSize);
    iter.writePointer(ptr(0));
    while (true) {
        const method = api.class_get_methods(klass, iter);
        if (method.isNull()) break;
        const mName = api.method_get_name(method).readCString();
        const pCount = api.method_get_param_count(method);
        if (mName === methodName && pCount === paramCount) {
            const fnPtr = method.readPointer(); // methodPointer @ offset 0
            console.log(`[+] Found ${className}.${methodName} @ ${fnPtr}`);
            return fnPtr;
        }
    }
    console.log(`[!] Method not found: ${className}.${methodName} (${paramCount} params)`);
    return ptr(0);
}

function waitForIl2cpp() {
    return new Promise((resolve) => {
        const timer = setInterval(() => {
            try {
                const mod = findModuleBase(LIB_NAME);
                if (!mod) return; // not loaded yet
                initApi();
                const domain = api.domain_get();
                if (!domain.isNull()) {
                    clearInterval(timer);
                    resolve();
                } else {
                    console.log('[*] libil2cpp loaded, waiting for domain...');
                }
            } catch (e) {
                console.log(`[*] waiting for il2cpp... (${e.message})`);
            }
        }, 2000);
    });
}

function waitForAssembly() {
    return new Promise((resolve) => {
        console.log('[*] Waiting for Assembly-CSharp (enter the game world on the phone)...');
        let listed = false;
        const timer = setInterval(() => {
            try {
                const domain = api.domain_get();
                const countPtr = Memory.alloc(Process.pointerSize);
                const assemblies = api.domain_get_assemblies(domain, countPtr);
                const count = countPtr.readU32();
                let found = false;
                const names = [];
                for (let i = 0; i < count; i++) {
                    const asm = assemblies.add(i * Process.pointerSize).readPointer();
                    const img = api.assembly_get_image(asm);
                    const name = api.image_get_name(img).readCString();
                    names.push(name);
                    if (name === 'Assembly-CSharp' || name === 'Assembly-CSharp.dll') {
                        found = true;
                    }
                }
                if (found) {
                    clearInterval(timer);
                    console.log(`[*] Assembly-CSharp found (${count} assemblies loaded).`);
                    resolve();
                    return;
                }
                if (!listed && count > 5) {
                    listed = true;
                    console.log(`[*] Loaded assemblies (${count}): ${names.join(', ')}`);
                }
            } catch (e) {
                console.log(`[*] waiting for assembly... (${e.message})`);
            }
        }, 3000);
    });
}

// ---------- hooks ----------

async function main() {
    console.log('[*] justice_hook v4 starting...');
    await waitForIl2cpp();
    console.log('[*] IL2CPP domain ready.');
    await waitForAssembly();
    console.log('[*] Installing hooks...\n');

    let hookCount = 0;

    // V4_POST_Login (static, 3 params)
    try {
        const v4Login = findMethodImpl(CLASS_NAME, 'V4_POST_Login', 3);
        if (!v4Login.isNull()) {
            Interceptor.attach(v4Login, {
                onEnter(args) {
                    console.log('\n========== V4_POST_Login called ==========');
                    const names = PARAMS['V4_POST_Login'];
                    for (let i = 0; i < 3; i++) {
                        console.log(`  ${names[i]}: ${trunc(readIl2cppString(args[i]))}`);
                    }
                    this.callTime = Date.now();
                },
                onLeave(retval) {
                    console.log(`  [return after ${Date.now() - this.callTime}ms]`);
                    console.log('========================================\n');
                }
            });
            hookCount++;
        }
    } catch (e) { console.log(`[!] V4_POST_Login hook failed: ${e.message}`); }

    // Sign (static, 2 params) — THE MOST IMPORTANT ONE
    try {
        const sign = findMethodImpl(CLASS_NAME, 'Sign', 2);
        if (!sign.isNull()) {
            Interceptor.attach(sign, {
                onEnter(args) {
                    console.log('\n---------- Sign called ----------');
                    const names = PARAMS['Sign'];
                    this.inputs = {};
                    for (let i = 0; i < 2; i++) {
                        const val = readIl2cppString(args[i]);
                        this.inputs[names[i]] = val;
                        console.log(`  ${names[i]}: ${trunc(val)}`);
                    }
                    this.startTime = Date.now();
                },
                onLeave(retval) {
                    const elapsed = Date.now() - this.startTime;
                    const output = readIl2cppString(retval);
                    console.log(`  => SIGN OUTPUT: ${trunc(output)}`);
                    console.log(`  (${elapsed}ms)`);
                    console.log('----------------------------------\n');
                    console.log(`[SIGN_DATA] input_content=${JSON.stringify(trunc(this.inputs.content, 2000))} input_apiName=${JSON.stringify(this.inputs.apiName)} output=${JSON.stringify(output)}`);
                }
            });
            hookCount++;
        }
    } catch (e) { console.log(`[!] Sign hook failed: ${e.message}`); }

    // GetDefaultParams (static, 0 params)
    try {
        const getDefault = findMethodImpl(CLASS_NAME, 'GetDefaultParams', 0);
        if (!getDefault.isNull()) {
            Interceptor.attach(getDefault, {
                onEnter(args) {
                    console.log('\n---------- GetDefaultParams called ----------');
                },
                onLeave(retval) {
                    console.log(`  [return] Dictionary object @ ${retval}`);
                    console.log('----------------------------------\n');
                }
            });
            hookCount++;
        }
    } catch (e) { console.log(`[!] GetDefaultParams hook failed: ${e.message}`); }

    // V3_POST_AllInOne (static, 1 param)
    try {
        const allInOne = findMethodImpl(CLASS_NAME, 'V3_POST_AllInOne', 1);
        if (!allInOne.isNull()) {
            Interceptor.attach(allInOne, {
                onEnter(args) {
                    console.log('\n========== V3_POST_AllInOne called ==========');
                    console.log(`  app_key: ${trunc(readIl2cppString(args[0]))}`);
                },
                onLeave(retval) {
                    console.log('============================================\n');
                }
            });
            hookCount++;
        }
    } catch (e) { console.log(`[!] V3_POST_AllInOne hook failed: ${e.message}`); }

    console.log(`\n[*] ${hookCount} hooks installed. Trigger a login in the game...`);
    console.log('[*] Look for [SIGN_DATA] lines.\n');
}

main();
