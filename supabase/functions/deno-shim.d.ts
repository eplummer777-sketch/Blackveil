// Minimal ambient declaration so `tsc` can type-check the Web Builder edge-function modules on a
// machine without the Deno toolchain. It describes only what those modules use and has no runtime
// effect: it is never imported and is only read by tsconfig.functions.json.
declare namespace Deno {
  function serve(handler: (req: Request) => Response | Promise<Response>): void;
  const env: { get(key: string): string | undefined };
}
