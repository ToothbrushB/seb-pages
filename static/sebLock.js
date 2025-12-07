function getSEBSecurityInfo() {
    SafeExamBrowser.security.updateKeys(didUpdateSEBSecurityInfo);
}

async function concatHash(a, b) {
    const msgUint8 = new TextEncoder().encode(a + b); // encode as (utf-8) Uint8Array
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8); // hash the message
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
}

function didUpdateSEBSecurityInfo() {
    // while a user may reasonably be able to inject the correct keys into JS variables, they cannot easily guess the user agent string to identify a real SEB instance
    const userAgent = window.navigator.userAgent;
    const bekExpected = document.querySelector('meta[name="seb-bek"]').content;
    const ckExpected = document.querySelector('meta[name="seb-ck"]').content;
    const uaHashedExpected = document.querySelector('meta[name="seb-ua"]').content;
    const url = window.location.origin + window.location.pathname; // Use origin and pathname to exclude query parameters and fragments
    // concatenate URL with each expected key and hash them with SHA 256, output as hex string
    Promise.all([
        concatHash(ckExpected, url),
        concatHash(bekExpected, url),
        concatHash(userAgent, url)
    ]).then(hashedKeys => {
        const [hashedCK, hashedBEK, hashedUA] = hashedKeys;
        var ckActual = SafeExamBrowser.security.configKey;
        var bekActual = SafeExamBrowser.security.browserExamKey;
        var sebClientVersion = SafeExamBrowser.version;
        if (hashedUA !== uaHashedExpected) {
            document.getElementById("header-content").innerHTML = "Security check failed: User Agent string does not match SEB instance.";
            document.getElementById("header-content").classList.remove("d-none");
            document.getElementById("header-content").classList.add("d-block");
        }
        if (hashedCK !== ckActual || hashedBEK !== bekActual) {
            document.getElementById("header-content").innerHTML = "Security check failed: Config Key or Browser Exam Key does not match expected values.";
            document.getElementById("header-content").classList.remove("d-none");
            document.getElementById("header-content").classList.add("d-block");
        }
        document.getElementById("seb-ck").innerText = "Config Key (hashed with URL): " + ckActual;
        document.getElementById("seb-bek").innerText = "Browser Exam Key (hashed with URL): " + bekActual;
        document.getElementById("seb-ua").innerText = "User Agent (hashed with URL): " + userAgent;
        document.getElementById("seb-version").innerText = "Application version: " + sebClientVersion;
    });
    
}
document.addEventListener('DOMContentLoaded', getSEBSecurityInfo)
