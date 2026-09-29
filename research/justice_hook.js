/**
 * JusticeSchool - Login Hook Script v5
 *
 * Changes from v4:
 *  - Proper Dictionary<string,string> enumeration (key-value pairs)
 *  - Sign return value: dumps raw type info + hex if not a valid string
 *  - Uses overload-aware method resolution
 *
 * Usage:
 *   frida -H 127.0.0.1:27042 -n Gadget -l research/frida/justice_hook.js
 */

'use strict';

// ---------- helpers ----------

function waitForIl2cpp() {
    return new Promise((resolve) => {
        const timer = setInterval(() => {
            try {
                const h = Module.getExportByName('libil2cpp.so', 'il2cpp_thread_attach');
                if (h) { clearInterval(timer); resolve(); }
            } catch (e) {}
        }, 500);
    });
}

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

// Enumerate Dictionary<string,string> via raw memory.
// Layout (from v4 debug): _entries at offset 24, _count nearby.
// Entry struct: hashCode(4) + next(4) + key(8) + value(8) = 24 bytes.
// Il2Cpp array: [klass(8)][monitor(8)][bounds(8)][max_length(8)][data...] (SZARRAY: data at +32)
function dumpDictionary(dictPtr) {
    if (dictPtr.isNull()) return '(null dict)';
    try {
        const out = {};
        // _entries array pointer at offset 24 (from v4 debug: entriesOffset=24)
        const entriesArr = dictPtr.add(24).readPointer();
        if (entriesArr.isNull()) return '(entries null)';
        // _count: try offset 32 (right after _entries pointer)
        const count = dictPtr.add(32).readU32();
        if (count > 1000) return `(suspicious count=${count})`;
        // Array data starts at +32 for SZARRAY
        const dataStart = entriesArr.add(32);
        for (let i = 0; i < count; i++) {
            const e = dataStart.add(i * 24);
            const hash = e.readS32();
            if (hash < 0) continue; // free slot
            const k = readIl2cppString(e.add(8).readPointer());
            const v = readIl2cppString(e.add(16).readPointer());
            out[k] = v;
        }
        return JSON.stringify(out, null, 1);
    } catch (e) {
        return `(dict dump failed: ${e.message})`;
    }
}

function findMethod(className, methodName, paramCount) {
    try {
        const asm = Il2Cpp.domain.assembly('Assembly-CSharp');
        const klass = asm.image.class(className);
        const methods = klass.methods.filter(m =>
            m.name === methodName && m.parameterCount === paramCount);
        if (methods.length === 0) {
            console.log(`[!] Not found: ${className}.${methodName} (${paramCount} params)`);
            return null;
        }
        for (const m of methods) {
            const sig = m.parameters.map(p => p.type.name).join(', ');
            console.log(`[?] ${className}.${methodName} overload: (${sig}) @ ${m.virtualAddress}`);
        }
        const chosen = methods[0];
        console.log(`[+] Using ${className}.${methodName} @ ${chosen.virtualAddress}`);
        // Print return type name
        try { console.log(`    return type: ${chosen.returnType.name}`); } catch (e) {}
        return chosen;
    } catch (e) {
        console.log(`[!] Error finding ${methodName}: ${e.message}`);
        return null;
    }
}

// ---------- main ----------

async function main() {
    console.log('[*] justice_hook v5 starting...');
    await waitForIl2cpp();
    const base = Process.enumerateModules()
        .filter(m => m.name === 'libil2cpp.so')[0];
    if (base) console.log(`[*] libil2cpp.so base @ ${base.base}`);

    // Wait for Assembly-CSharp
    console.log('[*] Waiting for Assembly-CSharp...');
    let asm = null;
    for (let i = 0; i < 120; i++) {
        try {
            asm = Il2Cpp.domain.assembly('Assembly-CSharp');
            if (asm) break;
        } catch (e) {}
        await new Promise(r => setTimeout(r, 1000));
    }
    if (!asm) { console.log('[!] Assembly-CSharp never loaded'); return; }
    console.log('[*] Assembly-CSharp found. Installing hooks...');

    const CN = 'ProtocolGame_HttpRequest';
    let n = 0;

    // V4_POST_Login(string, string, string)
    const v4 = findMethod(CN, 'V4_POST_Login', 3);
    if (v4) {
        Interceptor.attach(v4.virtualAddress, {
            onEnter(args) {
                console.log('\n========== V4_POST_Login ==========');
                console.log(`  app_key: ${trunc(readIl2cppString(args[0]))}`);
                console.log(`  content: ${trunc(readIl2cppString(args[1]))}`);
                console.log(`  apiName: ${trunc(readIl2cppString(args[2]))}`);
            },
            onLeave() { console.log('====================================\n'); }
        });
        n++;
    }

    // Sign(string, Dictionary<string,string>)
    const sign = findMethod(CN, 'Sign', 2);
    if (sign) {
        Interceptor.attach(sign.virtualAddress, {
            onEnter(args) {
                console.log('\n---------- Sign called ----------');
                this.c = readIl2cppString(args[0]);
                this.d = dumpDictionary(args[1]);
                console.log(`  content: ${trunc(this.c)}`);
                console.log(`  dict: ${this.d}`);
            },
            onLeave(retval) {
                let out;
                try {
                    const s = readIl2cppString(retval);
                    out = s.startsWith('(invalid') ? `(RAW_PTR=${retval} hex=[${retval.readByteArray(32).join(' ')}])` : s;
                } catch (e) { out = `(read failed: ${e.message})`; }
                console.log(`  => SIGN OUTPUT: ${trunc(out, 300)}`);
                console.log('----------------------------------');
                console.log(`[SIGN_DATA] content=${JSON.stringify(trunc(this.c, 2000))} dict=${this.d} output=${JSON.stringify(trunc(out, 500))}\n`);
            }
        });
        n++;
    }

    // GetDefaultParams()
    const gdp = findMethod(CN, 'GetDefaultParams', 0);
    if (gdp) {
        Interceptor.attach(gdp.virtualAddress, {
            onEnter() { console.log('\n---------- GetDefaultParams ----------'); },
            onLeave(retval) {
                console.log(`  [return] ${dumpDictionary(retval)}`);
                console.log('----------------------------------\n');
            }
        });
        n++;
    }

    // V3_POST_AllInOne(string)
    const aio = findMethod(CN, 'V3_POST_AllInOne', 1);
    if (aio) {
        Interceptor.attach(aio.virtualAddress, {
            onEnter(args) {
                console.log('\n========== V3_POST_AllInOne ==========');
                console.log(`  app_key: ${trunc(readIl2cppString(args[0]))}`);
                console.log('====================================\n');
            }
        });
        n++;
    }

    console.log(`\n[*] ${n} hooks installed. Trigger login in game. Look for [SIGN_DATA].\n`);
}

if (typeof Il2Cpp === 'undefined') {
    console.log('[!] Il2Cpp bridge not found.');
} else {
    main();
}
