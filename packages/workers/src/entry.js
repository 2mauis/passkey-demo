// 零 JS 入口（D16，待 F1 核实 wrangler alias 之后再给接入方用）。
// wrangler.toml: main = "node_modules/@pkauth/workers/dist/entry.js"
// [alias] "pkauth:upstream" = "./src/index.js"
import upstream from 'pkauth:upstream';
import { protect } from './index.js';

export default protect(upstream);
