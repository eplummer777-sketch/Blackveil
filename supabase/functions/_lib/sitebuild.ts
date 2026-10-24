type FileMap = Record<string, string>;

export function resolveLocal(ref: string, from = ""): string | null {
  if (/^(?:[a-z]+:|\/\/|#|data:)/i.test(ref)) return null;
  const clean = ref.split(/[?#]/)[0];
  if (!clean) return null;
  const dir = !clean.startsWith("/") && from.includes("/") ? from.slice(0, from.lastIndexOf("/") + 1) : "";
  const parts: string[] = [];
  for (const seg of (dir + clean).split("/")) {
    if (seg === "..") parts.pop();
    else if (seg && seg !== ".") parts.push(seg);
  }
  return parts.join("/") || null;
}

export const BRIDGE = `<script>(function(){
var send=function(m){try{parent.postMessage(Object.assign({bv:1},m),"*")}catch(e){}};
window.addEventListener("error",function(e){send({type:"error",message:String(e.message||"Script error"),line:e.lineno||0})});
window.addEventListener("unhandledrejection",function(e){var r=e.reason;send({type:"error",message:"Unhandled promise rejection: "+(r&&r.message?r.message:String(r))})});
var ce=console.error;console.error=function(){send({type:"console",message:Array.prototype.map.call(arguments,function(a){try{return typeof a==="string"?a:(a&&a.message)||JSON.stringify(a)}catch(x){return String(a)}}).join(" ")});return ce.apply(console,arguments)};
document.addEventListener("click",function(e){var a=e.target&&e.target.closest&&e.target.closest("a[href]");if(!a)return;var h=a.getAttribute("href");if(!h||/^(?:[a-z]+:|\\/\\/|#)/i.test(h))return;e.preventDefault();send({type:"nav",href:h})},true);
})();</script>`;

export function buildPreview(files: FileMap, entry = "index.html"): { html: string; missing: string[] } | null {
  const page = files[entry];
  if (page === undefined) return null;
  const missing: string[] = [];
  let html = page.replace(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*>/gi, (tag, href: string) => {
    if (!/rel=["']?stylesheet/i.test(tag)) return tag;
    const p = resolveLocal(href, entry);
    if (!p) return tag;
    if (!(p in files)) { missing.push(p); return tag; }
    return `<style data-file="${p}">\n${files[p].replace(/<\/style/gi, '<\\/style')}\n</style>`;
  });
  html = html.replace(/<script\b([^>]*)\bsrc=["']([^"']+)["']([^>]*)>\s*<\/script>/gi, (tag, pre: string, src: string, post: string) => {
    const p = resolveLocal(src, entry);
    if (!p) return tag;
    if (!(p in files)) { missing.push(p); return tag; }
    return `<script${pre}${post} data-file="${p}">\n${files[p].replace(/<\/script/gi, '<\\/script')}\n</script>`;
  });
  html = /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, (h) => h + BRIDGE) : BRIDGE + html;
  return { html, missing };
}
