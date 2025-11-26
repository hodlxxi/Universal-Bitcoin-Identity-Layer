// Classic "Matrix rain" background
// Usage: const stop = startMatrixRain(canvas);
function startMatrixRain(canvas) {
  if (!canvas) return () => {};
  const ctx = canvas.getContext('2d');

  const CHARS = '01';
  let width = 0, height = 0, fontSize = 16;
  let cols = 0;
  let drops = [];
  let speeds = [];
  let raf = null;

  const TRAIL_ALPHA = 0.08;     // trail strength
  const SPEED_MIN = 0.5;
  const SPEED_MAX = 1.5;
  const COLOR = '#00ff88';

  function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;

    // Pick font size based on width so it scales nicely
    fontSize = Math.max(14, Math.min(24, Math.floor(width / 80)));
    ctx.font = fontSize + 'px monospace';
    ctx.textBaseline = 'top';

    cols = Math.floor(width / fontSize);
    drops = new Array(cols).fill(0).map(() => randInt(-20, height / fontSize));
    speeds = new Array(cols).fill(0).map(() => Math.random() * (SPEED_MAX - SPEED_MIN) + SPEED_MIN);
  }

  function draw() {
    ctx.fillStyle = `rgba(0,0,0,${TRAIL_ALPHA})`;
    ctx.fillRect(0, 0, width, height);
    ctx.fillStyle = COLOR;

    for (let i = 0; i < cols; i++) {
      const ch = CHARS.charAt((Math.random() * CHARS.length) | 0);
      const x = i * fontSize, y = drops[i] * fontSize;
      ctx.fillText(ch, x, y);
      drops[i] += speeds[i];

      if (y > height + randInt(0, 100)) {
        drops[i] = randInt(-20, -5);
        speeds[i] = Math.random() * (SPEED_MAX - SPEED_MIN) + SPEED_MIN;
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
