/* TAP_PROBE_V1: on-screen tap debug, activates only with ?tapdebug=1 */
(function(){
  try{
    const p = new URLSearchParams(location.search);
    if (p.get("tapdebug") !== "1") return;

    const box = document.createElement("pre");
    box.id = "taplog";
    box.style.cssText = "position:fixed;left:8px;right:8px;bottom:8px;max-height:40vh;overflow:auto;z-index:999999;background:rgba(0,0,0,.75);border:1px solid rgba(0,255,0,.35);border-radius:10px;padding:8px;color:#7CFF7C;font:12px/1.25 ui-monospace,Menlo,monospace;white-space:pre-wrap;";
    document.body.appendChild(box);

    function log(s){
      const t = new Date().toISOString().slice(11,19);
      box.textContent = (t + " " + s + "\n") + box.textContent;
    }

    log("tapdebug ON");
    log("UA: " + navigator.userAgent);

    window.addEventListener("error", (e)=> log("window.onerror: " + (e.message||e.error||"") ));

    function info(ev){
      const tgt = ev.target;
      const id = tgt && tgt.id ? "#"+tgt.id : "";
      const cls = tgt && tgt.className ? "."+String(tgt.className).replace(/\s+/g,".") : "";
      log(ev.type + " -> " + (tgt ? (tgt.tagName + id + cls) : "null"));
    }

    ["pointerdown","pointerup","touchstart","touchend","click"].forEach((t)=>{
      document.addEventListener(t, info, true);
    });

    // Quick overlay check for lnBtn
    setTimeout(()=>{
      const b = document.getElementById("lnBtn");
      if (!b) return log("lnBtn: NOT FOUND");
      const r = b.getBoundingClientRect();
      const el = document.elementFromPoint(r.left + r.width/2, r.top + r.height/2);
      log("lnBtn rect: " + JSON.stringify({x:Math.round(r.x),y:Math.round(r.y),w:Math.round(r.width),h:Math.round(r.height)}));
      log("elementFromPoint(center): " + (el ? (el.tagName + (el.id?("#"+el.id):"") ) : "null"));
    }, 600);

  }catch(e){}
})();
