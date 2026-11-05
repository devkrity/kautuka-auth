import assert from "node:assert/strict";
import test from "node:test";

import { isAllowedGatewayOrigin } from "../public/return-path.js";

test("gateway origin allows secure or local canonical origins only", () => {
  for (const origin of ["https://public.example", "http://localhost:20229", "http://192.168.1.20", "http://172.16.0.1", "http://172.31.255.255", "http://kautuka.local:5000", "http://[::1]:20229", "http://[fd00::1]"]) {
    assert.equal(isAllowedGatewayOrigin(origin), true, origin);
  }
  for (const origin of ["http://public.example", "http://8.8.8.8", "http://172.15.255.255", "http://172.32.0.1", "http://2130706433", "http://0x7f000001", "http://127.0.0.1:80", "http://gateway.office.local", "http://public.example.", "https://user@public.example", "https://public.example/path", "https://public.example?x=1", "https://public.example#fragment", "http://[::2]", "http://xn--bcher-kva.local", "http://localhost\\@public.example"]) {
    assert.equal(isAllowedGatewayOrigin(origin), false, origin);
  }
});
