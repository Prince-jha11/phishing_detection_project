// A simple background service worker
chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard extension installed and ready.");
});
