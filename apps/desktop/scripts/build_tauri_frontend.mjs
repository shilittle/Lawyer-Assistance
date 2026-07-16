import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const desktopDirectory = path.resolve(scriptDirectory, "..");

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: desktopDirectory,
    env: process.env,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${path.basename(command)} failed with exit code ${result.status}`);
  }
}

run(process.env.LAWYER_ASSISTANCE_PYTHON || "python", ["scripts/verify_legal_resource.py"]);
run(process.execPath, [path.join(desktopDirectory, "node_modules", "typescript", "bin", "tsc"), "--noEmit"]);
run(process.execPath, [path.join(desktopDirectory, "node_modules", "vite", "bin", "vite.js"), "build"]);
run(process.execPath, ["scripts/verify_frontend_dist.mjs"]);
