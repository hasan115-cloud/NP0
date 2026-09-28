#!/usr/bin/env node
import { spawn } from "child_process";
import path from "path";

const args = process.argv.slice(2);
let port = "3000";
let hostname = "0.0.0.0";
const extraArgs = [];

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === "--port" || arg === "-p") {
    port = args[++i] || port;
  } else if (arg === "--host" || arg === "-H" || arg === "--hostname") {
    hostname = args[++i] || hostname;
  } else if (arg.startsWith("--port=")) {
    port = arg.split("=")[1];
  } else if (arg.startsWith("--host=") || arg.startsWith("--hostname=")) {
    hostname = arg.split("=")[1];
  } else if (arg === "--turbo" || arg === "--turbopack" || arg === "--webpack") {
    extraArgs.push(arg);
  }
}

const nextArgs = ["dev", "-p", port, "-H", hostname, ...extraArgs];
const nextBin = path.resolve(process.cwd(), "node_modules", "next", "dist", "bin", "next");

const child = spawn(process.execPath, [nextBin, ...nextArgs], {
  stdio: "inherit",
  env: process.env,
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code ?? 0);
  }
});
