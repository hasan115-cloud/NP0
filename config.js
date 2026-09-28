// PhishGuard Extension Configuration
// Pre-configured by PhishGuard Server on package download or customizable via Extension popup settings
const PHISHGUARD_DEFAULT_CONFIG = {
    SERVER_URL: "http://localhost:3000"
};

if (typeof self !== "undefined") {
    self.PHISHGUARD_DEFAULT_CONFIG = PHISHGUARD_DEFAULT_CONFIG;
}
if (typeof window !== "undefined") {
    window.PHISHGUARD_DEFAULT_CONFIG = PHISHGUARD_DEFAULT_CONFIG;
}
if (typeof module !== "undefined" && module.exports) {
    module.exports = PHISHGUARD_DEFAULT_CONFIG;
}
