import fs from "fs";
import path from "path";
import JSZip from "jszip";

const EXTENSION_DIR = path.resolve(process.cwd(), "extension");

export async function generateExtensionZip(currentServerUrl: string): Promise<Buffer> {
  const zip = new JSZip();

  if (!fs.existsSync(EXTENSION_DIR)) {
    throw new Error("Extension directory not found at " + EXTENSION_DIR);
  }

  const files = fs.readdirSync(EXTENSION_DIR);
  const cleanServerUrl = (currentServerUrl || "").replace(/\/$/, "");

  for (const filename of files) {
    const filePath = path.join(EXTENSION_DIR, filename);
    const stat = fs.statSync(filePath);

    if (stat.isFile()) {
      if (filename === "config.js") {
        // Dynamically inject the active production server origin into config.js
        const dynamicConfig = `// PhishGuard Extension Configuration
// Automatically configured by PhishGuard Enterprise Security Hub
const PHISHGUARD_DEFAULT_CONFIG = {
    SERVER_URL: "${cleanServerUrl}"
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
`;
        zip.file(filename, dynamicConfig);
      } else if (filename === "background.js") {
        // Ensure default BACKEND_URL starts with the current server URL
        let bgCode = fs.readFileSync(filePath, "utf-8");
        bgCode = bgCode.replace(
          /let BACKEND_URL = ["'][^"']*["'];/,
          `let BACKEND_URL = "${cleanServerUrl}";`
        );
        zip.file(filename, bgCode);
      } else if (filename === "popup.js") {
        // Ensure default currentServer starts with current server URL
        let popupCode = fs.readFileSync(filePath, "utf-8");
        popupCode = popupCode.replace(
          /let currentServer\s*=\s*["'][^"']*["'];/,
          `let currentServer = "${cleanServerUrl}";`
        );
        zip.file(filename, popupCode);
      } else if (filename === "popup.html") {
        // Update input placeholder to match production server
        let popupHtml = fs.readFileSync(filePath, "utf-8");
        popupHtml = popupHtml.replace(
          /placeholder=["'][^"']*localhost[^"']*["']/i,
          `placeholder="${cleanServerUrl}"`
        );
        zip.file(filename, popupHtml);
      } else if (
        filename.toLowerCase().endsWith(".png") ||
        filename.toLowerCase().endsWith(".jpg") ||
        filename.toLowerCase().endsWith(".ico")
      ) {
        // Any binary image asset must be copied as raw bytes
        const bin = fs.readFileSync(filePath);
        zip.file(filename, bin);
      } else {
        const content = fs.readFileSync(filePath, "utf-8");
        zip.file(filename, content);
      }
    }
  }

  const zipBuffer = await zip.generateAsync({
    type: "nodebuffer",
    compression: "DEFLATE",
    compressionOptions: { level: 9 }
  });

  return zipBuffer;
}
