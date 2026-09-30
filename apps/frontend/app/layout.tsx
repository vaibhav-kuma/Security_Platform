import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Security Assessment Platform",
  description: "Authorized penetration testing and bug-bounty assessment platform",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-background font-sans antialiased">
        {children}
      </body>
    </html>
  );
}