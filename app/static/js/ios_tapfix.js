/* ios_tapfix.js: helps iOS Safari translate taps reliably (no-op elsewhere) */
(function(){
  try{
    var ua = navigator.userAgent || "";
    var isiOS = /iPhone|iPod|iPad/.test(ua);
    if(!isiOS) return;

    function bind(id, fnName){
      var el = document.getElementById(id);
      if(!el || el.dataset.iosTapfix) return;
      el.dataset.iosTapfix = "1";

      var lastTouch = 0;

      el.addEventListener("touchend", function(ev){
        lastTouch = Date.now();
        ev.preventDefault();
        ev.stopPropagation();
        var fn = window[fnName];
        if(typeof fn === "function") fn();
      }, {passive:false});

      // Avoid double-trigger if click still fires
      el.addEventListener("click", function(ev){
        if(Date.now() - lastTouch < 600){
          ev.preventDefault();
          ev.stopPropagation();
          return;
        }
      }, true);
    }

    function init(){
      bind("lnBtn", "loginWithLightning");
      bind("nostrBtn", "loginWithNostr");
    }

    if(document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
  }catch(e){}
})();
