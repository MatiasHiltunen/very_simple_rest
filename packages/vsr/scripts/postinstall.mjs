import { ensureNativeBinary, isRepoDevelopmentInstall } from "../src/native.mjs";

if (!isRepoDevelopmentInstall()) {
  try {
    ensureNativeBinary();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
