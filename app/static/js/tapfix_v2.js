/* TAPFIX_V2: robust tap binding without double-fire */
(function(){
  function once(fn){
    let last = 0;
    return function(){
      const now = Date.now();
      if (now - last < 600) return;
      last = now;
      try { fn(); } catch(e) { try{ console.error("tapfix fn error:", e); }catch(_){} }
    };
  }
  function bind(id, fnName){
    const el = document.getElementById(id);
    if (!el || el.dataset.tapfixv2) return;
    el.dataset.tapfixv2 = "1";
    el.style.pointerEvents = "auto";
    el.style.position = el.style.position || "relative";
    el.style.zIndex = el.style.zIndex || "50";

    const fire = once(function(){
      const fn = window[fnName];
      if (typeof fn === "function") fn();
      else try{ console.warn("tapfix: missing fn", fnName); }catch(_){}
    });

    // Use multiple events; don’t preventDefault (iOS can get weird)
    el.addEventListener("pointerup", function(ev){ ev.stopPropagation(); fire(); }, true);
    el.addEventListener("touchend",  function(ev){ ev.stopPropagation(); fire(); }, {capture:true, passive:true});
    el.addEventListener("click",     function(ev){ ev.stopPropagation(); fire(); }, true);
  }

  function disableBg(){
    try{
      const bg =
        document.getElementById("matrix-bg") ||
        document.getElementById("matrix-canvas") ||
        document.querySelector("canvas#matrix-bg, canvas#matrix-canvas, #matrix-bg canvas, #matrix-canvas canvas");
      if (bg) bg.style.pointerEvents = "none";
    }catch(e){}
  }

  function init(){
    disableBg();
    bind("lnBtn", "loginWithLightning");
    bind("nostrBtn", "loginWithNostr");
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
