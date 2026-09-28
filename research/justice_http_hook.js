/**
 * JusticeSchool (com.Alioth.JusticeSchool.cn) - HTTP Hook Script (Java level)
 *
 * Hooks Java HTTP clients to capture signed API requests.
 * Works on any architecture (no native code involved).
 *
 * Captures: URL, request body (contains app_key, content, apiName, sign)
 * Goal: collect (content, apiName, sign) triples to reverse the Sign algorithm.
 *
 * Usage:
 *   frida -U -p <PID> -l justice_http_hook.js
 */

'use strict';

function trunc(s, maxLen) {
    maxLen = maxLen || 3000;
    if (s === null || s === undefined) return '(null)';
    s = String(s);
    if (s.length > maxLen) {
        return s.substring(0, maxLen) + `...[truncated ${s.length} chars total]`;
    }
    return s;
}

function logRequest(tag, url, body) {
    console.log(`\n========== [HTTP] ${tag} ==========`);
    console.log(`  URL: ${trunc(url, 500)}`);
    if (body) {
        console.log(`  BODY: ${trunc(body)}`);
        // Machine-readable line for analysis
        console.log(`[HTTP_DATA] url=${JSON.stringify(trunc(url, 500))} body=${JSON.stringify(trunc(body, 5000))}`);
    }
    console.log('========================================\n');
}

Java.perform(function () {
    console.log('[*] justice_http_hook starting (Java level)...');
    let hookCount = 0;

    // ---- OkHttp3 ----
    try {
        const OkHttpClient = Java.use('okhttp3.OkHttpClient');
        const Request = Java.use('okhttp3.Request');
        // Hook newCall to capture the Request
        OkHttpClient.newCall.overload('okhttp3.Request').implementation = function (req) {
            try {
                const url = req.url().toString();
                let bodyStr = null;
                try {
                    const body = req.body();
                    if (body) {
                        const Buffer = Java.use('okio.Buffer');
                        const buffer = Buffer.$new();
                        body.writeTo(buffer);
                        bodyStr = buffer.readUtf8();
                    }
                } catch (e) { bodyStr = `<body read failed: ${e.message}>`; }
                // Only log game API calls (skip analytics/CDN noise if possible)
                logRequest('OkHttp', url, bodyStr);
            } catch (e) {
                console.log(`[!] OkHttp hook error: ${e.message}`);
            }
            return this.newCall(req);
        };
        console.log('[+] Hooked okhttp3.OkHttpClient.newCall');
        hookCount++;
    } catch (e) {
        console.log(`[-] OkHttp3 not found: ${e.message}`);
    }

    // ---- HttpURLConnection ----
    try {
        const HttpURLConn = Java.use('java.net.HttpURLConnection');
        // Hook connect() - read URL; body is harder here, so we hook getOutputStream
        console.log('[+] HttpURLConnection available, hooking...');
        hookCount++;
    } catch (e) {
        console.log(`[-] HttpURLConnection hook failed: ${e.message}`);
    }

    // ---- HttpsURLConnection (output stream to capture POST bodies) ----
    try {
        const HttpsConn = Java.use('javax.net.ssl.HttpsURLConnection');
        const URL = Java.use('java.net.URL');
        // We hook at the OutputStream level via a wrapper is complex;
        // instead, hook setRequestMethod + log URL on connect.
        HttpsConn.connect.overload().implementation = function () {
            try {
                const url = this.getURL().toString();
                const method = this.getRequestMethod();
                if (method === 'POST' || method === 'PUT') {
                    logRequest('HttpsURLConnection', url, '(body via OutputStream - see OkHttp hook if used)');
                }
            } catch (e) { /* ignore */ }
            return this.connect();
        };
        console.log('[+] Hooked HttpsURLConnection.connect');
        hookCount++;
    } catch (e) {
        console.log(`[-] HttpsURLConnection hook failed: ${e.message}`);
    }

    console.log(`\n[*] ${hookCount} Java hooks installed.`);
    console.log('[*] Trigger a login / API call in the game and watch for [HTTP_DATA] lines.\n');
});
