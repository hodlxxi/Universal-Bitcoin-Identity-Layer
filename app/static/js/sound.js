(function(){
  if (window.HODLXXI_PLAY_SOUND) return;

  const POOL = [];
  let pending = null;

  function _play(url, volume){
    try{
      const a = new Audio(url);
      a.preload = "auto";
      a.playsInline = true;
      if (typeof volume === "number") a.volume = Math.max(0, Math.min(1, volume));

      const idx = POOL.push(a) - 1;
      const cleanup = () => { POOL[idx] = null; };
      a.addEventListener("ended", cleanup, {once:true});
      a.addEventListener("error", cleanup, {once:true});

      const pr = a.play();
      if (pr && pr.catch) pr.catch((e)=>{
        pending = url;
        cleanup();
        console.warn("[sound blocked]", url, e);
      });
    }catch(e){
      pending = url;
      console.warn("[sound exception]", url, e);
    }
  }

  window.HODLXXI_PLAY_SOUND = function(url, volume){
    if(!url) return;
    _play(url, volume);
  };

  function flush(){
    if(!pending) return;
    const u = pending;
    pending = null;
    _play(u);
  }

  ["pointerdown","touchstart","click","keydown"].forEach((ev)=>{
    window.addEventListener(ev, flush, {passive:true});
  });
})();
