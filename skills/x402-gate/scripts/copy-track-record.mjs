import { copyFileSync, mkdirSync } from "node:fs";

const src = new URL("../src/track_record_vk.json", import.meta.url);
const distDir = new URL("../dist/", import.meta.url);
const dest = new URL("../dist/track_record_vk.json", import.meta.url);

mkdirSync(distDir, { recursive: true });
copyFileSync(src, dest);
