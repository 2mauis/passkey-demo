// 接入方胶水（§4.4）。不含判断逻辑。配置在 wrangler 的 PKAUTH_* 里。
import upstream from './baseline.js';
import { protect } from '@pkauth/workers';

export default protect(upstream);
