/* The same lower-resolution Gargantua-inspired WebGL renderer used by the
   NEXUS landing page. It replaces the 2D fallback when WebGL2 is available. */
(()=>{
  if(typeof createGR3BlackHole!=='function')return;
  const canvas=document.createElement('canvas');canvas.id='nexus-gr-blackhole';
  Object.assign(canvas.style,{position:'fixed',inset:'0',width:'100vw',height:'100vh',zIndex:'0',pointerEvents:'none',opacity:'.98'});
  document.body.prepend(canvas);
  // Five HDR render targets are used per frame. Cap their real resolution,
  // rather than merely making the black hole look smaller, to keep the miner
  // controls responsive on integrated GPUs and high-DPI screens.
  // 60fps target: render the five-pass HDR simulation at a deliberately
  // compact internal size, then let the browser scale/bloom it beautifully.
  // This is the performance lever that matters; apparent zoom is not.
  const resize=()=>{const scale=Math.min(.44,Math.max(.34,innerWidth/2600));const maxWidth=840;canvas.width=Math.min(maxWidth,Math.round(innerWidth*scale));canvas.height=Math.round(canvas.width*(innerHeight/innerWidth))};
  resize();
  const gr=createGR3BlackHole(canvas,{mouseFracX:.35,mouseFracY:.5,maxFps:60,bloomScale:.28,screenOffset:{x:.280,y:.037}});
  if(!gr){canvas.remove();return}
  const fallback=document.getElementById('nexus-blackhole');if(fallback)fallback.style.display='none';
  addEventListener('resize',resize);function frame(t){if(!document.hidden)gr.render(t);requestAnimationFrame(frame)}requestAnimationFrame(frame);
})();
