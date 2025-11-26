// 0/1 space-warp background
// Usage: const stop = startMatrixWarp(canvas);
function startMatrixWarp(canvas) {
  if (!canvas) return () => {};
  const ctx = canvas.getContext('2d');

  const CHARS = ['0','1'];
  let width = 0, height = 0, particles = [];
  let raf = null;

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
    particles = [];
    for (let i = 0; i < 400; i++) {
      particles.push({
        x: (Math.random() - 0.5) * width,
        y: (Math.random() - 0.5) * height,
        z: Math.random() * 800 + 100
      });
    }
  }

  function draw() {
    ctx.fillStyle = 'rgba(0,0,0,0.25)';
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = '#00ff88';
    for (let p of particles) {
      const scale = 200 / p.z;
      const x2d = width / 2 + p.x * scale;
      const y2d = height / 2 + p.y * scale;
      const size = Math.max(8 * scale, 1);
      ctx.font = size + 'px monospace';
      ctx.fillText(CHARS[Math.random() > 0.5 ? 1 : 0], x2d, y2d);
      p.z -= 5;
      if (p.z < 1) {
        p.x = (Math.random() - 0.5) * width;
        p.y = (Math.random() - 0.5) * height;
        p.z = 800;
      }
    }
    raf = requestAnimationFrame(draw);
  }

  function onVis() {
    if (document.hidden) { if (raf) cancelAnimationFrame(raf), raf = null; }
    else { if (!raf) raf = requestAnimationFrame(draw); }
  }

  function onResize() { resize(); }

  window.addEventListener('resize', onResize);
  document.addEventListener('visibilitychange', onVis);
  resize();
  raf = requestAnimationFrame(draw);

  return function stop() {
    if (raf) cancelAnimationFrame(raf), raf = null;
    window.removeEventListener('resize', onResize);
    document.removeEventListener('visibilitychange', onVis);
  };
}
