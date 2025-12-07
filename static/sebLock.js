  function getSEBSecurityInfo() {
    try {
        SafeExamBrowser.security.updateKeys(didUpdateSEBSecurityInfo);
    } catch (error) {
        document.getElementById("seb-check").innerHTML = "SEB Security information could not be retrieved!";
        document.getElementById("seb-check").classList.remove("alert-success");
        document.getElementById("seb-check").classList.add("alert-danger", "bad");
    }
}

async function concatHash(a, b) {
    const msgUint8 = new TextEncoder().encode(a + b); // encode as (utf-8) Uint8Array
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8); // hash the message
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
}

let sebOk = false;

function didUpdateSEBSecurityInfo() {
    // while a user may reasonably be able to inject the correct keys into JS variables, they cannot easily guess the user agent string to identify a real SEB instance
    // extract substring from UA string between [ and ] if present
    const userAgentFull = window.navigator.userAgent;
    const userAgentMatch = userAgentFull.match(/\[(.*?)\]/);
    const userAgent = userAgentMatch ? userAgentMatch[1] : userAgentFull;
    const url = window.location.origin + window.location.pathname; // Use origin and pathname to exclude query parameters and fragments
    var ckActual = SafeExamBrowser.security.configKey;
    var bekActual = SafeExamBrowser.security.browserExamKey;
    var sebClientVersion = SafeExamBrowser.version;
    document.getElementById("seb-ck").innerText = "Config Key (hashed with URL): " + ckActual;
    document.getElementById("seb-bek").innerText = "Browser Exam Key (hashed with URL): " + bekActual;
    document.getElementById("seb-version").innerText = "Application version: " + sebClientVersion;
    concatHash(url, userAgent).then(hashedUA => {document.getElementById("seb-ua").innerText = "User Agent (hashed with URL): " + hashedUA;})

    try {
      const bekExpected = document.querySelector('meta[name="seb-bek"]').content;
      const ckExpected = document.querySelector('meta[name="seb-ck"]').content;
      const uaHashedExpected = document.querySelector('meta[name="seb-ua"]').content;
      Promise.all([
        concatHash(url, ckExpected),
        concatHash(url, bekExpected),
        concatHash(url, userAgent)
    ]).then(hashedKeys => {
        const [hashedCK, hashedBEK, hashedUA] = hashedKeys;
        if (hashedUA !== uaHashedExpected) {
            document.getElementById("seb-check").innerHTML = "Security check failed: User Agent string does not match SEB instance.";
            document.getElementById("seb-check").classList.remove("alert-success");
            document.getElementById("seb-check").classList.add("alert-danger", "bad");
            sebOk = false;
        } else if (hashedCK !== ckActual || hashedBEK !== bekActual) {
            document.getElementById("seb-check").innerHTML = "Security check failed: Config Key or Browser Exam Key does not match expected values.";
            document.getElementById("seb-check").classList.remove("alert-success");
            document.getElementById("seb-check").classList.add("alert-danger", "bad");
            sebOk = false;
        } else {
            document.getElementById("seb-check").innerHTML = "🔒 Exam Secure";
            document.getElementById("seb-check").classList.remove("alert-danger", "bad");
            document.getElementById("seb-check").classList.add("alert-success");
            sebOk = true;
        }
        
    });
    } catch (error) {
      document.getElementById("seb-check").innerHTML = "SEB info not embedded in page";
      document.getElementById("seb-check").classList.remove("alert-success");
      document.getElementById("seb-check").classList.add("alert-danger", "bad");
    }
    

    
    
}
document.addEventListener('DOMContentLoaded', getSEBSecurityInfo)
// get seb security info every 1 sec
setInterval(getSEBSecurityInfo, 1000);