import { NextRequest, NextResponse } from "next/server";
import { generateExtensionZip } from "@/lib/extensionPackager";

export async function GET(req: NextRequest) {
  const host = req.headers.get("host") || "localhost:3000";
  const proto = req.headers.get("x-forwarded-proto") || "http";
  const serverUrl = process.env.APP_URL ? process.env.APP_URL.replace(/\/$/, "") : `${proto}://${host}`;

  try {
    const zipBuffer = await generateExtensionZip(serverUrl);
    return new NextResponse(zipBuffer, {
      status: 200,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/zip",
        "Content-Disposition": 'attachment; filename="phishguard-extension.zip"',
        "Content-Length": zipBuffer.length.toString(),
      },
    });
  } catch (err: any) {
    return NextResponse.json({ error: "Failed to generate extension package", message: err?.message }, { status: 500 });
  }
}
