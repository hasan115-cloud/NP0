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

  for (const filename of files) {
    const filePath = path.join(EXTENSION_DIR, filename);
    const stat = fs.statSync(filePath);

    if (stat.isFile()) {
      if (filename === "config.js") {
        // Dynamically inject the active server origin into config.js
        const dynamicConfig = `// PhishGuard Extension Configuration
// Automatically configured by PhishGuard Enterprise Security Hub
const PHISHGUARD_DEFAULT_CONFIG = {
    SERVER_URL: "${currentServerUrl}"
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
          /let BACKEND_URL = ["'][^"']+["'];/,
          `let BACKEND_URL = "${currentServerUrl}";`
        );
        zip.file(filename, bgCode);
      } else if (filename.toLowerCase().endsWith(".png") || filename.toLowerCase().endsWith(".jpg") || filename.toLowerCase().endsWith(".ico")) {
        // Any binary image asset (icon16/48/128.png, icon.png, etc.) must be
        // copied as raw bytes — reading it as utf-8 text corrupts the PNG.
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
