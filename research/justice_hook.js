/**
 * JusticeSchool (com.Alioth.JusticeSchool.cn) - Login Hook Script v3
 *
 * NO frida-il2cpp-bridge, NO frida-compile needed.
 * Uses raw IL2CPP C API exports directly.
 *
 * Hooks:
 *  - ProtocolGame_HttpRequest.V4_POST_Login(app_key, content, apiName)
 *  - ProtocolGame_HttpRequest.Sign(content, apiName)
 *  - ProtocolGame_HttpRequest.GetDefaultParams()
 *  - ProtocolGame_HttpRequest.V3_POST_AllInOne(app_key)
 *
 * Usage:
 *   frida -U -f com.Alioth.JusticeSchool.cn -l justice_hook.js
 *   (then type %resume in the REPL)
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

// ---------- raw IL2CPP API (no bridge) ----------

let api = null;

function initApi() {
    const exp = (n) => Module.getExportByName('libil2cpp.so', n);
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
        if (name === 'Assembly-CSharp') { image = img; break; }
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

function waitForIl2cppDomain() {
    return new Promise((resolve) => {
        const timer = setInterval(() => {
            try {
                Module.getExportByName('libil2cpp.so', 'il2cpp_domain_get');
                initApi();
                const domain = api.domain_get();
                if (!domain.isNull()) {
                    clearInterval(timer);
                    resolve();
                }
            } catch (e) {
                // not ready yet
            }
        }, 500);
    });
}

// ---------- hooks ----------

async function main() {
    await waitForIl2cppDomain();
    console.log('[*] IL2CPP domain ready, installing hooks...\n');

    let hookCount = 0;

    // V4_POST_Login (static, 3 params)
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

    // Sign (static, 2 params) — THE MOST IMPORTANT ONE
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

    // GetDefaultParams (static, 0 params)
    const getDefault = findMethodImpl(CLASS_NAME, 'GetDefaultParams', 0);
    if (!getDefault.isNull()) {
        Interceptor.attach(getDefault, {
            onEnter(args) {
                console.log('\n---------- GetDefaultParams called ----------');
            },
            onLeave(retval) {
                console.log(`  [return] Dictionary object @ ${retval}`);
                console.log('  (inspect with a debugger for contents)');
                console.log('----------------------------------\n');
            }
        });
        hookCount++;
    }

    // V3_POST_AllInOne (static, 1 param)
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

    console.log(`\n[*] ${hookCount} hooks installed. Trigger a login in the game...`);
    console.log('[*] Look for [SIGN_DATA] lines.\n');
}

main();
