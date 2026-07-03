/** Registers the .js-extension resolve hook before the test files load. */
import { register } from "node:module";
register("./hooks.mjs", import.meta.url);
