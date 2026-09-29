import { NextRequest, NextResponse } from "next/server";
import { generateExtensionZip } from "@/lib/extensionPackager";
import { getPublicServerUrl } from "@/lib/serverUrl";

export async function GET(req: NextRequest) {
  const serverUrl = getPublicServerUrl(req);

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
    return NextResponse.json(
      { error: "Failed to generate extension package", message: err?.message },
      { status: 500 }
    );
  }
}
