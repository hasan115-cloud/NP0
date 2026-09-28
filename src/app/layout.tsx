import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PhishGuard Enterprise Security Hub",
  description:
    "Centralized enterprise client-server security monitoring, telemetry, threat detection, and policy management for PhishGuard Chrome Extensions.",
  openGraph: {
    title: "PhishGuard Enterprise Security Hub",
    description:
      "Centralized enterprise client-server security monitoring, telemetry, threat detection, and policy management for PhishGuard Chrome Extensions.",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "PhishGuard Enterprise Security Hub",
    description:
      "Centralized enterprise client-server security monitoring, telemetry, threat detection, and policy management for PhishGuard Chrome Extensions.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-[#000000] text-neutral-100 font-sans antialiased">
        {children}
      </body>
    </html>
  );
}
