function l(t,n=""){if(/^(?:[a-z]+:|\/\/|#|data:)/i.test(t))return null;const i=t.split(/[?#]/)[0];if(!i)return null;const a=!i.startsWith("/")&&n.includes("/")?n.slice(0,n.lastIndexOf("/")+1):"",r=[];for(const e of(a+i).split("/"))e===".."?r.pop():e&&e!=="."&&r.push(e);return r.join("/")||null}const u=`<script>(function(){
var send=function(m){try{parent.postMessage(Object.assign({bv:1},m),"*")}catch(e){}};
window.addEventListener("error",function(e){send({type:"error",message:String(e.message||"Script error"),line:e.lineno||0})});
window.addEventListener("unhandledrejection",function(e){var r=e.reason;send({type:"error",message:"Unhandled promise rejection: "+(r&&r.message?r.message:String(r))})});
var ce=console.error;console.error=function(){send({type:"console",message:Array.prototype.map.call(arguments,function(a){try{return typeof a==="string"?a:(a&&a.message)||JSON.stringify(a)}catch(x){return String(a)}}).join(" ")});return ce.apply(console,arguments)};
document.addEventListener("click",function(e){var a=e.target&&e.target.closest&&e.target.closest("a[href]");if(!a)return;var h=a.getAttribute("href");if(!h||/^(?:[a-z]+:|\\/\\/|#)/i.test(h))return;e.preventDefault();send({type:"nav",href:h})},true);
})();<\/script>`;function d(t,n="index.html"){const i=t[n];if(i===void 0)return null;const a=[];let r=i.replace(/<link\b[^>]*\bhref=["']([^"']+)["'][^>]*>/gi,(e,o)=>{if(!/rel=["']?stylesheet/i.test(e))return e;const s=l(o,n);return s?s in t?`<style data-file="${s}">
${t[s].replace(/<\/style/gi,"<\\/style")}
</style>`:(a.push(s),e):e});return r=r.replace(/<script\b([^>]*)\bsrc=["']([^"']+)["']([^>]*)>\s*<\/script>/gi,(e,o,s,p)=>{const c=l(s,n);return c?c in t?`<script${o}${p} data-file="${c}">
${t[c].replace(/<\/script/gi,"<\\/script")}
<\/script>`:(a.push(c),e):e}),r=/<head[^>]*>/i.test(r)?r.replace(/<head[^>]*>/i,e=>e+u):u+r,{html:r,missing:a}}export{d as b,l as r};
