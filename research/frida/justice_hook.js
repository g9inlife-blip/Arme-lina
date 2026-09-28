/**
 * JusticeSchool (com.Alioth.JusticeSchool.kr) - Login Hook Script v2
 * 
 * Hooks:
 *  - ProtocolGame_HttpRequest.V4_POST_Login(app_key, content, apiName)
 *  - ProtocolGame_HttpRequest.Sign(content, apiName)
 *  - ProtocolGame_HttpRequest.GetDefaultParams()
 *  - ProtocolGame_HttpRequest.V3_POST_AllInOne(app_key)
 * 
 * Usage:
 *   frida -U -f com.Alioth.JusticeSchool.kr -l justice_hook.js --no-pause
 * 
 * Output: Captures Sign inputs/outputs for algorithm reverse-engineering,
 *         plus the full login request structure.
 * 
 * The game uses IL2CPP. We resolve methods by name at runtime via Il2Cpp API,
 * so no hardcoded addresses are needed.
 */

'use strict';

// Parameter names (from static analysis, NEWVERSION-003)
const PARAMS = {
    'V4_POST_Login': ['app_key', 'content', 'apiName'],
    'Sign': ['content', 'apiName'],
    'GetDefaultParams': [],
    'V3_POST_AllInOne': ['app_key'],
};

// Wait for IL2CPP to be ready
function waitForIl2cpp() {
    return new Promise((resolve) => {
        const timer = setInterval(() => {
            try {
                const handle = Module.getExportByName('libil2cpp.so', 'il2cpp_thread_attach');
                if (handle) {
                    clearInterval(timer);
                    resolve();
                }
            } catch (e) {
                // libil2cpp not loaded yet
            }
        }, 500);
    });
}

// Helper to read a C# string from Il2Cpp String* pointer
function readIl2cppString(ptr) {
    if (ptr.isNull()) return '(null)';
    try {
        // Il2CppString: [klass(8)][monitor(8)][length(4)][chars...]
        const length = ptr.add(16).readU32();
        if (length > 10000) return `(string too long: ${length} chars)`;
        return ptr.add(20).readUtf16String(length);
    } catch (e) {
        return `<unreadable:${e.message}>`;
    }
}

// Helper to get method info
function getMethod(className, methodName, paramCount) {
    try {
        const assembly = Il2Cpp.domain.assembly('Assembly-CSharp');
        const klass = assembly.image.class(className);
        const method = klass.method(methodName, paramCount);
        if (!method) {
            console.log(`[!] Method not found: ${className}.${methodName} (${paramCount} params)`);
            return null;
        }
        console.log(`[+] Found ${className}.${methodName} @ ${method.virtualAddress}`);
        return method;
    } catch (e) {
        console.log(`[!] Error finding ${methodName}: ${e.message}`);
        return null;
    }
}

// Truncate long strings for readability
function trunc(s, maxLen = 500) {
    if (s === null || s === undefined) return '(null)';
    s = String(s);
    if (s.length > maxLen) {
        return s.substring(0, maxLen) + `...[truncated ${s.length} chars total]`;
    }
    return s;
}

async function main() {
    await waitForIl2cpp();
    console.log('[*] IL2CPP ready, installing hooks...\n');

    const className = 'ProtocolGame_HttpRequest';
    let hookCount = 0;

    // Hook V4_POST_Login (static, 3 params)
    const v4Login = getMethod(className, 'V4_POST_Login', 3);
    if (v4Login) {
        Interceptor.attach(v4Login.virtualAddress, {
            onEnter(args) {
                console.log('\n========== V4_POST_Login called ==========');
                const names = PARAMS['V4_POST_Login'];
                for (let i = 0; i < 3; i++) {
                    const val = readIl2cppString(args[i]);
                    console.log(`  ${names[i]}: ${trunc(val)}`);
                }
                this.callTime = Date.now();
            },
            onLeave(retval) {
                const elapsed = Date.now() - this.callTime;
                console.log(`  [return after ${elapsed}ms]`);
                console.log('========================================\n');
            }
        });
        hookCount++;
    }

    // Hook Sign (static, 2 params) - THE MOST IMPORTANT ONE
    const sign = getMethod(className, 'Sign', 2);
    if (sign) {
        Interceptor.attach(sign.virtualAddress, {
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
                // Also log in a machine-readable format for analysis
                console.log(`[SIGN_DATA] input_content=${JSON.stringify(trunc(this.inputs.content, 2000))} input_apiName=${JSON.stringify(this.inputs.apiName)} output=${JSON.stringify(output)}`);
            }
        });
        hookCount++;
    }

    // Hook GetDefaultParams (static, 0 params)
    const getDefault = getMethod(className, 'GetDefaultParams', 0);
    if (getDefault) {
        Interceptor.attach(getDefault.virtualAddress, {
            onEnter(args) {
                console.log('\n---------- GetDefaultParams called ----------');
            },
            onLeave(retval) {
                // Return is a Dictionary - try to read it
                // For now, just note it was called; dictionary reading is complex
                console.log(`  [return] Dictionary object @ ${retval}`);
                console.log('  (Use debugger to inspect dictionary contents)');
                console.log('----------------------------------\n');
            }
        });
        hookCount++;
    }

    // Hook V3_POST_AllInOne (static, 1 param)
    const allInOne = getMethod(className, 'V3_POST_AllInOne', 1);
    if (allInOne) {
        Interceptor.attach(allInOne.virtualAddress, {
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

    console.log(`\n[*] ${hookCount} hooks installed successfully.`);
    console.log('[*] Now trigger a login in the game...');
    console.log('[*] Look for [SIGN_DATA] lines - those are the key to reverse-engineering Sign.\n');
}

// Frida-il2cpp-bridge provides global Il2Cpp
if (typeof Il2Cpp === 'undefined') {
    console.log('[!] Il2Cpp bridge not found.');
    console.log('    Install: npm install frida-il2cpp-bridge');
    console.log('    Then add at the top of this script:');
    console.log('        const { Il2Cpp } = require("frida-il2cpp-bridge");');
    console.log('        Il2Cpp.perform(() => { main(); });');
} else {
    main();
}
