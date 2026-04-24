import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
const PACKAGE_JSON = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
);
const REPO_ROOT = resolve(PACKAGE_ROOT, "../..");

function nativeBinaryPath(root) {
  return join(root, "bin", process.platform === "win32" ? "vsr.exe" : "vsr");
}

function nativeVersionFile(root) {
  return join(root, "version.txt");
}

function readInstalledVersion(root) {
  const versionFile = nativeVersionFile(root);
  if (!existsSync(versionFile)) {
    return null;
  }

  return readFileSync(versionFile, "utf8").trim() || null;
}

export function isRepoDevelopmentInstall() {
  return (
    existsSync(join(REPO_ROOT, "Cargo.toml")) &&
    existsSync(join(REPO_ROOT, "crates", "rest_api_cli", "Cargo.toml"))
  );
}

export function ensureNativeBinary() {
  const root = join(PACKAGE_ROOT, ".native");
  const binary = nativeBinaryPath(root);

  if (existsSync(binary) && readInstalledVersion(root) === PACKAGE_JSON.version) {
    return binary;
  }

  mkdirSync(root, { recursive: true });

  const result = spawnSync(
    "cargo",
    [
      "install",
      "vsra",
      "--version",
      PACKAGE_JSON.version,
      "--locked",
      "--root",
      root,
      "--force"
    ],
    {
      cwd: PACKAGE_ROOT,
      env: {
        ...process.env,
        CARGO_TARGET_DIR: join(root, "target")
      },
      stdio: "inherit"
    }
  );

  if (result.error) {
    if (result.error.code === "ENOENT") {
      throw new Error(
        "cargo is required to install the native vsr binary for the npm package"
      );
    }
    throw result.error;
  }

  if (result.status !== 0) {
    throw new Error(`cargo install vsra exited with status ${result.status ?? 1}`);
  }

  writeFileSync(nativeVersionFile(root), `${PACKAGE_JSON.version}\n`);
  return binary;
}

export function resolveNativeInvocation() {
  const overridden = process.env.VSR_NATIVE_BINARY;
  if (overridden) {
    if ([".cjs", ".js", ".mjs"].includes(extname(overridden).toLowerCase())) {
      return {
        command: process.execPath,
        argsPrefix: [overridden],
        cwd: process.cwd()
      };
    }

    return {
      command: overridden,
      argsPrefix: [],
      cwd: process.cwd()
    };
  }

  if (isRepoDevelopmentInstall()) {
    return {
      command: "cargo",
      argsPrefix: [
        "run",
        "--quiet",
        "--manifest-path",
        join(REPO_ROOT, "Cargo.toml"),
        "-p",
        "vsra",
        "--"
      ],
      cwd: process.cwd()
    };
  }

  return {
    command: ensureNativeBinary(),
    argsPrefix: [],
    cwd: process.cwd()
  };
}
