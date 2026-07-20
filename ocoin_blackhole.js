/* Canvas bloom/lensing effect: big enough to be a visual identity, but kept
   to the right so wallet fields remain easy to read. */
(()=>{
  const c=document.createElement('canvas'),g=c.getContext('2d');c.id='nexus-blackhole';document.body.prepend(c);
  const dust=Array.from({length:125},(_,i)=>({a:Math.random()*Math.PI*2,r:115+Math.random()*470,s:.00025+Math.random()*.0008,z:Math.random()*1.8+.35,h:i%3}));
  const glow=['#50f5ed','#bd83ff','#ff4f9a'];
  function arc(cx,cy,r,sy,start,end,col,w,blur=0){g.save();g.strokeStyle=col;g.lineWidth=w;g.shadowColor=col;g.shadowBlur=blur;g.beginPath();g.ellipse(cx,cy,r,r*sy,0,start,end);g.stroke();g.restore()}
  function draw(ms){let w=c.width=innerWidth,h=c.height=innerHeight,t=ms*.001,cx=w*.725,cy=h*.48,scale=Math.min(w,h)/820;g.clearRect(0,0,w,h);
    // Deep gravitational haze behind the disk.
    let halo=g.createRadialGradient(cx,cy,10,cx,cy,560*scale);halo.addColorStop(0,'rgba(0,0,0,.86)');halo.addColorStop(.18,'rgba(15,15,42,.20)');halo.addColorStop(.48,'rgba(71,34,112,.10)');halo.addColorStop(1,'rgba(0,0,0,0)');g.fillStyle=halo;g.fillRect(0,0,w,h);
    g.globalCompositeOperation='screen';
    // Broad blurred accretion atmosphere, then hard chromatic edges.
    for(const [r,col,st,en] of [[450,'rgba(51,234,239,.22)',.1,1.04],[395,'rgba(187,95,255,.22)',2.0,3.18],[340,'rgba(255,64,143,.20)',4.05,5.36]])arc(cx,cy,r*scale,.33,st+t*.08,en+t*.08,col,38*scale,48*scale);
    for(const [r,col,st,en] of [[406,'#47f6ea',.04,.94],[356,'#b584ff',1.97,3.19],[300,'#ff559b',4.06,5.24],[252,'#39d7ff',5.65,6.16]])arc(cx,cy,r*scale,.34,st+t*.13,en+t*.13,col,5.4*scale,19*scale);
    // Fast particles make the disk feel alive rather than like a static logo.
    for(const p of dust){let a=p.a+t*p.s*900,x=cx+Math.cos(a)*p.r*scale,y=cy+Math.sin(a)*p.r*.335*scale;g.fillStyle=['rgba(90,255,243,.86)','rgba(205,151,255,.84)','rgba(255,111,172,.8)'][p.h];g.shadowColor=g.fillStyle;g.shadowBlur=8;g.fillRect(x,y,p.z*1.8,p.z*1.8)}
    // Lensed back and front bands meet around the pure-black horizon.
    arc(cx,cy,195*scale,.27,Math.PI*.12,Math.PI*.90,'rgba(67,244,234,.82)',12*scale,26*scale);arc(cx,cy,182*scale,.27,Math.PI*1.10,Math.PI*1.91,'rgba(255,82,159,.82)',12*scale,26*scale);
    g.globalCompositeOperation='source-over';let core=108*scale;let coreGlow=g.createRadialGradient(cx,cy,core*.35,cx,cy,core*1.55);coreGlow.addColorStop(0,'#000');coreGlow.addColorStop(.66,'#000');coreGlow.addColorStop(.82,'rgba(0,0,0,.92)');coreGlow.addColorStop(1,'rgba(1,2,10,0)');g.fillStyle=coreGlow;g.beginPath();g.arc(cx,cy,core*1.55,0,Math.PI*2);g.fill();g.fillStyle='#000';g.shadowColor='#000';g.shadowBlur=32*scale;g.beginPath();g.ellipse(cx,cy,core*1.02,core*.88,0,0,Math.PI*2);g.fill();
    requestAnimationFrame(draw)}requestAnimationFrame(draw);
})();
