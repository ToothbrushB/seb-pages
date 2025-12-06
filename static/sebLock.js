function getSEBSecurityInfo() {
    SafeExamBrowser.security.updateKeys(didUpdateSEBSecurityInfo);
}

async function hashKeyWithURL(key, url) {
    const msgUint8 = new TextEncoder().encode(key + url); // encode as (utf-8) Uint8Array
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8); // hash the message
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
}

function didUpdateSEBSecurityInfo() {
    const bekExpected = document.querySelector('meta[name="seb-bek"]').content;
    const ckExpected = document.querySelector('meta[name="seb-ck"]').content;
    const url = window.location.origin + window.location.pathname; // Use origin and pathname to exclude query parameters and fragments
    // concatenate URL with each expected key and hash them with SHA 256, output as hex string
    Promise.all([
        hashKeyWithURL(ckExpected, url),
        hashKeyWithURL(bekExpected, url)
    ]).then(hashedKeys => {
        const [hashedCK, hashedBEK] = hashedKeys;
        var pageConfigKey = SafeExamBrowser.security.configKey;
        var pageBrowserExamKey = SafeExamBrowser.security.browserExamKey;
        var sebClientVersion = SafeExamBrowser.version;
        var securityInformation = 'Config Key (hashed with URL): ' + pageConfigKey + '<br/>Browser Exam Key (hashed with URL): ' + pageBrowserExamKey + '<br/>Application version: ' + sebClientVersion + '<br/>Expected Config Key: ' + ckExpected + '<br/>Expected Browser Exam Key: ' + bekExpected + '<br/>Computed Hashed Config Key: ' + hashedCK + '<br/>Computed Hashed Browser Exam Key: ' + hashedBEK;
        document.getElementById("securityInformation").innerHTML = securityInformation;
    });
    
}
document.addEventListener('DOMContentLoaded', getSEBSecurityInfo)
