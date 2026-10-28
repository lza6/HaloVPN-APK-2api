// HaloVPN: 抓 AES 密钥 (SignUtils.getDData 明文) + v7.a.a 解密入参/结果
Java.perform(function () {
    try {
        var SU = Java.use("org.strongswan.android.utils.SignUtils");
        SU.getDData.implementation = function (s) {
            var r = this.getDData(s);
            console.log("[getDData] in=" + s + "  out=" + r);
            return r;
        };
        console.log("[+] SignUtils.getDData hooked");
    } catch (e) { console.log("[-] getDData hook fail: " + e); }

    try {
        var A = Java.use("v7.a");
        A.a.implementation = function (ct, key) {
            var r = this.a(ct, key);
            console.log("[v7.a.a] key=" + key + " ct=" + ct + " pt=" + r);
            return r;
        };
        console.log("[+] v7.a.a hooked");
    } catch (e) { console.log("[-] v7.a hook fail: " + e); }
});
