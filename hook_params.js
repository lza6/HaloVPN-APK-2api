Java.perform(function () {
    try {
        var R = Java.use("com.thehot.halovpnpro.utils.RSAUtils");
        R.encryptedDataOnJava.implementation = function (plain, pub) {
            var r = this.encryptedDataOnJava(plain, pub);
            console.log("[RSA_ENC] plaintext=" + plain + " | pub=" + pub.substring(0, 30) + " | out=" + r);
            return r;
        };
        console.log("[+] RSAUtils.encryptedDataOnJava hooked");
    } catch (e) { console.log("[-] rsa hook fail: " + e); }
    try {
        var SU = Java.use("org.strongswan.android.utils.SignUtils");
        SU.getDData.implementation = function (s) { var r = this.getDData(s); console.log("[getDData] " + s + " -> " + r); return r; };
        SU.getPublicKey.implementation = function () { var r = this.getPublicKey(); console.log("[getPublicKey] -> " + r); return r; };
        SU.getEData.implementation = function (s) { var r = this.getEData(s); console.log("[getEData] " + s + " -> " + r); return r; };
        console.log("[+] SignUtils hooked");
    } catch (e) { console.log("[-] signutils hook fail: " + e); }
    try {
        var A = Java.use("v7.a");
        A.a.implementation = function (ct, key) { var r = this.a(ct, key); console.log("[AES_DEC] key=" + key + " ct=" + ct + " pt=" + r); return r; };
        console.log("[+] v7.a hooked");
    } catch (e) { console.log("[-] v7a hook fail: " + e); }
});

Java.perform(function () {
    try {
        var D = Java.use("v6.d");
        D.$init.overload('android.content.Context', 'java.lang.String', 'java.lang.String', 'java.util.HashMap').implementation = function (ctx, host, path, map) {
            console.log("[HTTP] " + host + path + " params=" + map.toString());
            return this.$init(ctx, host, path, map);
        };
        console.log("[+] v6.d hooked");
    } catch (e) { console.log("[-] v6.d hook fail: " + e); }
});
