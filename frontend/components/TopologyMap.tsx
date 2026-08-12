"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PointerEvent as ReactPointerEvent, MouseEvent as ReactMouseEvent } from "react";
import { Asset, DashboardToolSummary, RelatedAssetGroup, ScanJob } from "../types/scan";
import { toolLabel } from "../lib/labels";
import { categoryInfo } from "../lib/categories";

/* ── Canvas constants ──────────────────────────────────────────────── */
const SVG_W = 800;
const SVG_H = 320;
const ROOT_Y = 46;
const CAT_Y = 144;
const SPAWN_Y = 246;
const ROOT_R = 26;
const CAT_R = 22;
const SPAWN_R = 15;
const MIN_ZOOM = 0.5;
const MAX_ZOOM = 4;

/* ── Status → visuals ──────────────────────────────────────────────── */
function statusStroke(status: string | null): string {
  switch (status) {
    case "completed": return "var(--success)";
    case "running": return "var(--high)";
    case "pending": return "var(--text-secondary)";
    case "failed": return "var(--critical)";
    default: return "var(--border)";
  }
}
function statusFill(status: string | null): string {
  switch (status) {
    case "completed": return "var(--success-dim)";
    case "running": return "var(--high-dim)";
    case "pending": return "var(--panel-dim)";
    case "failed": return "var(--critical-dim)";
    default: return "var(--panel-dim)";
  }
}
function statusFr(status: string | null): string {
  switch (status) {
    case "completed": return "Terminé";
    case "running": return "En cours";
    case "pending": return "En attente";
    case "failed": return "Échec";
    default: return "—";
  }
}

function toolEmoji(tool: string): string {
  const m: Record<string, string> = {
    whois:"🔍",shodan:"🖥",censys:"🌐",reverse_dns:"🔄",email_security:"📧",
    theharvester:"🌾",subfinder:"🔎",amass:"📡",merklemap:"🗺",httpx:"🌍",
    nmap:"🔌",holehe:"📋",ssl_checker:"🔒",certspotter:"📜",sublist3r:"🌐",
    dnsdumpster:"📡",publicwww:"💻",cloudscraper:"☁️",csprecon:"🛡️",
    waymore:"📚",subover:"⚠️",passivedns:"🔎",
  };
  return m[tool] || "⚙";
}
function assetEmoji(t: string): string {
  const m: Record<string,string>={domain:"🌐",subdomain:"🔗",ip:"🖥",email:"📧",service:"⚡",technology:"📊"};
  return m[t]||"•";
}

type StatusFilter = "all" | "completed" | "running" | "pending" | "failed";
interface TooltipState { x:number;y:number;title:string;lines:string[];accent:string; }

/* ── Props ──────────────────────────────────────────────────────────── */
interface Props {
  asset: Asset;
  toolSummary: DashboardToolSummary[];
  relatedAssets: RelatedAssetGroup[];
  onSelectJob: (job: ScanJob) => void;
  onJumpToAsset: (assetId: number) => void;
  onCancelJob?: (jobId: number) => void;
  onSelectCategory?: (category: string) => void;
  treeMode?: boolean;
}

/* ── Component ─────────────────────────────────────────────────────── */
export default function TopologyMap({ asset, toolSummary, relatedAssets, onSelectJob, onJumpToAsset, onCancelJob, onSelectCategory, treeMode }: Props) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const pointers = useRef<Map<number,{x:number;y:number}>>(new Map());
  const panState = useRef<{lastX:number;lastY:number}|null>(null);
  const panMoved = useRef(false);
  const pinchState = useRef<{dist:number}|null>(null);
  const [transform, setTransform] = useState({x:0,y:0,k:1});
  const [isPanning, setIsPanning] = useState(false);
  const [hoveredKey, setHoveredKey] = useState<string|null>(null);
  const [tooltip, setTooltip] = useState<TooltipState|null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [search, setSearch] = useState("");

  /* ── Build graph data — grouped by CATEGORY ───────────────────── */
  // Group tools by category, pick worst status and aggregate
  const categoryNodes = useMemo(() => {
    const cats: Record<string, { tools: DashboardToolSummary[]; status: string | null; job: ScanJob | null }> = {};
    for (const ts of toolSummary) {
      if (!ts.latest_job && !ts.applicable) continue;
      const cat = ts.category || "other";
      if (!cats[cat]) cats[cat] = { tools: [], status: null, job: null };
      cats[cat].tools.push(ts);
      // Worst status: running > failed > completed > pending > null
      const st = ts.latest_status;
      if (st === "running") cats[cat].status = "running";
      else if (st === "failed" && cats[cat].status !== "running") cats[cat].status = "failed";
      else if (st === "completed" && !cats[cat].status) cats[cat].status = "completed";
      else if (st === "pending" && !cats[cat].status) cats[cat].status = "pending";
      if (ts.latest_job && !cats[cat].job) cats[cat].job = ts.latest_job;
    }
    return Object.entries(cats).map(([cat, cdata], i) => {
      const info = categoryInfo(cat);
      const done = cdata.tools.filter(t => t.latest_status === "completed" || t.latest_status === "completed_no_data" || t.latest_status === "failed").length;
      return {
        key: `cat-${cat}`,
        category: cat,
        label: info.label,
        emoji: info.emoji,
        color: info.color,
        bgColor: info.bgColor,
        status: cdata.status,
        job: cdata.job,
        toolCount: cdata.tools.length,
        doneCount: done,
        tools: cdata.tools,
      };
    });
  }, [toolSummary]);

  const spawnedNodes = useMemo(() =>
    relatedAssets.filter(ra => ra.relation === "child" || ra.relation === "both").map(ra => ({
      key: `spawn-${ra.asset.id}`,
      assetId: ra.asset.id,
      value: ra.asset.value,
      type: ra.asset.asset_type,
      emoji: assetEmoji(ra.asset.asset_type),
      status: ra.summary.latest_status,
      parentTool: ra.links.length > 0 ? ra.links[0].tool : null,
      // Map parent tool to its category
      parentCategory: (() => {
        const t = ra.links.length > 0 ? ra.links[0].tool : null;
        if (!t) return null;
        const ts = toolSummary.find(s => s.tool === t);
        return ts?.category || "other";
      })(),
    })), [relatedAssets, toolSummary]);

  const catToIdx = useMemo(() => {
    const m = new Map<string,number>(); categoryNodes.forEach((cn,i) => m.set(cn.category,i)); return m;
  }, [categoryNodes]);

  const spawnParentCatIdx = useMemo(() => {
    const m = new Map<string,number>();
    spawnedNodes.forEach(sn => { if (sn.parentCategory) { const i = catToIdx.get(sn.parentCategory); if (i !== undefined) m.set(sn.key,i); } });
    return m;
  }, [spawnedNodes, catToIdx]);

  const catChildren = useMemo(() => {
    const m = new Map<number,string[]>();
    spawnParentCatIdx.forEach((idx,key) => { const a = m.get(idx)??[]; a.push(key); m.set(idx,a); });
    return m;
  }, [spawnParentCatIdx]);

  /* ── Layout ────────────────────────────────────────────────────── */
  const catCount = categoryNodes.length;
  const catSpacing = catCount > 1 ? Math.min(130, (SVG_W - 80) / (catCount - 1)) : 0;
  const catTotalW = (catCount - 1) * catSpacing;
  const catX = useCallback((i:number) => catCount === 1 ? SVG_W/2 : SVG_W/2 - catTotalW/2 + i*catSpacing, [catCount,catTotalW,catSpacing]);
  const spawnCount = spawnedNodes.length;
  const spawnSpacing = spawnCount > 1 ? Math.min(130, (SVG_W - 60) / (spawnCount - 1)) : 0;
  const spawnTotalW = (spawnCount - 1) * spawnSpacing;
  const spawnX = useCallback((i:number) => spawnCount === 1 ? SVG_W/2 : SVG_W/2 - spawnTotalW/2 + i*spawnSpacing, [spawnCount,spawnTotalW,spawnSpacing]);
  function curvePath(x1:number,y1:number,x2:number,y2:number) { const m=(y1+y2)/2; return `M${x1} ${y1} C${x1} ${m},${x2} ${m},${x2} ${y2}`; }

  /* ── Filtering ─────────────────────────────────────────────────── */
  const q = search.trim().toLowerCase();
  const catMatches = useCallback((cn:typeof categoryNodes[number]) => {
    const sOk = statusFilter==="all" || cn.status===statusFilter;
    const qOk = q==="" || cn.label.toLowerCase().includes(q) || cn.category.toLowerCase().includes(q);
    return sOk && qOk;
  }, [statusFilter,q]);
  const spawnMatches = useCallback((sn:typeof spawnedNodes[number]) => {
    const sOk = statusFilter==="all" || sn.status===statusFilter;
    const qOk = q==="" || sn.value.toLowerCase().includes(q);
    return sOk && qOk;
  }, [statusFilter,q]);
  const hasFilter = statusFilter!=="all" || q!=="";

  /* ── Zoom / pan ────────────────────────────────────────────────── */
  const clamp = (v:number,min:number,max:number) => Math.min(max,Math.max(min,v));
  const clientToViewBox = useCallback((cx:number,cy:number) => {
    const svg = svgRef.current; if (!svg) return {x:0,y:0};
    const r = svg.getBoundingClientRect();
    return {x:(cx-r.left)*(SVG_W/r.width), y:(cy-r.top)*(SVG_H/r.height)};
  }, []);
  const zoomBy = useCallback((cx:number,cy:number,factor:number) => {
    const p = clientToViewBox(cx,cy);
    setTransform(t => { const k2=clamp(t.k*factor,MIN_ZOOM,MAX_ZOOM); return {k:k2, x:p.x-(p.x-t.x)/t.k*k2, y:p.y-(p.y-t.y)/t.k*k2}; });
  }, [clientToViewBox]);
  const resetView = () => setTransform({x:0,y:0,k:1});
  const zoomCenter = (f:number) => { const r = wrapperRef.current?.getBoundingClientRect(); if (r) zoomBy(r.left+r.width/2,r.top+r.height/2,f); };

  useEffect(() => {
    const el = wrapperRef.current; if (!el) return;
    const onWheel = (e:WheelEvent) => { e.preventDefault(); zoomBy(e.clientX,e.clientY,Math.exp(-e.deltaY*0.0015)); };
    el.addEventListener("wheel", onWheel, {passive:false});
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomBy]);

  const onPointerDown = (e:ReactPointerEvent<SVGSVGElement>) => {
    // Only capture if not clicking a node
    const target = e.target as Element;
    if (target.closest('[data-nocapture]')) return;
    pointers.current.set(e.pointerId,{x:e.clientX,y:e.clientY});
    if (pointers.current.size===1) { panState.current={lastX:e.clientX,lastY:e.clientY}; setIsPanning(true); }
    else if (pointers.current.size===2) { const ps=Array.from(pointers.current.values()); pinchState.current={dist:Math.hypot(ps[0].x-ps[1].x,ps[0].y-ps[1].y)}; panState.current=null; }
  };
  const onPointerMove = (e:ReactPointerEvent<SVGSVGElement>) => {
    if (!pointers.current.has(e.pointerId)) return;
    pointers.current.set(e.pointerId,{x:e.clientX,y:e.clientY});
    if (pointers.current.size===2 && pinchState.current) {
      const ps=Array.from(pointers.current.values()); const d=Math.hypot(ps[0].x-ps[1].x,ps[0].y-ps[1].y);
      zoomBy((ps[0].x+ps[1].x)/2,(ps[0].y+ps[1].y)/2,d/(pinchState.current.dist||1)); pinchState.current.dist=d; return;
    }
    if (pointers.current.size===1 && panState.current) {
      const r=svgRef.current?.getBoundingClientRect(); const sx=r?SVG_W/r.width:1; const sy=r?SVG_H/r.height:1;
      const dx=(e.clientX-panState.current.lastX)*sx, dy=(e.clientY-panState.current.lastY)*sy;
      panState.current={lastX:e.clientX,lastY:e.clientY}; setTransform(t=>({...t,x:t.x+dx,y:t.y+dy}));
    }
  };
  const onPointerUp = (e:ReactPointerEvent<SVGSVGElement>) => {
    pointers.current.delete(e.pointerId);
    if (pointers.current.size<2) pinchState.current=null;
    if (pointers.current.size===1) { const r=Array.from(pointers.current.values())[0]; panState.current={lastX:r.x,lastY:r.y}; }
    else if (pointers.current.size===0) { panState.current=null; setIsPanning(false); }
  };

  const showTooltip = (e:ReactMouseEvent,title:string,lines:string[],accent:string) => {
    const w=wrapperRef.current; if (!w) return;
    const nr=(e.currentTarget as Element).getBoundingClientRect(), wr=w.getBoundingClientRect();
    setTooltip({x:nr.left+nr.width/2-wr.left, y:nr.top-wr.top, title,lines,accent});
  };

  if (categoryNodes.length===0 && spawnedNodes.length===0) {
    return <div className="panel card-pad mb-5"><p className="eyebrow mb-3">Topologie de découverte</p><p className="text-xs text-center py-6" style={{color:"var(--text-secondary)"}}>Lancez une analyse pour voir la chaîne de découverte.</p></div>;
  }

  const filters: {key:StatusFilter;label:string;color:string}[] = [
    {key:"failed",label:"Échec",color:"var(--critical)"},{key:"completed",label:"Terminé",color:"var(--success)"},
    {key:"running",label:"En cours",color:"var(--high)"},{key:"pending",label:"En attente",color:"var(--text-secondary)"},
  ];

  return (
    <div className="panel mb-5 overflow-hidden">
      <div className="px-5 py-3 flex items-center justify-between gap-3 flex-wrap" style={{borderBottom:"1px solid var(--border)"}}>
        <p className="eyebrow" style={{marginBottom:0}}>Topologie de découverte</p>
        <div className="flex items-center gap-3 flex-wrap">
          <input type="text" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Filtrer…" className="text-[11px] px-2 py-1 rounded"
            style={{background:"var(--panel-dim)",border:"1px solid var(--border)",color:"var(--text-primary)",outline:"none",width:140}} />
          <span className="text-[11px]" style={{color:"var(--text-secondary)"}}>
            {categoryNodes.length} catégorie{categoryNodes.length!==1?"s":""} · {spawnedNodes.length} actif{spawnedNodes.length!==1?"s":""}
          </span>
        </div>
      </div>
      <div ref={wrapperRef} className="relative" style={{background:"var(--panel-dim)",touchAction:"none"}}>
        <div className="absolute top-3 right-3 flex flex-col gap-1 z-10" style={{userSelect:"none"}}>
          <button onClick={()=>zoomCenter(1.25)} className="w-6 h-6 flex items-center justify-center rounded text-xs font-bold" style={{background:"var(--panel)",border:"1px solid var(--border)",color:"var(--text-primary)"}}>+</button>
          <button onClick={()=>zoomCenter(0.8)} className="w-6 h-6 flex items-center justify-center rounded text-xs font-bold" style={{background:"var(--panel)",border:"1px solid var(--border)",color:"var(--text-primary)"}}>−</button>
          <button onClick={resetView} className="w-6 h-6 flex items-center justify-center rounded text-[10px] font-bold" style={{background:"var(--panel)",border:"1px solid var(--border)",color:"var(--text-secondary)"}}>⤾</button>
        </div>
        <div className="absolute bottom-3 right-3 z-10 text-[10px] px-1.5 py-0.5 rounded" style={{background:"var(--panel)",border:"1px solid var(--border)",color:"var(--text-secondary)"}}>{Math.round(transform.k*100)}%</div>
        <svg ref={svgRef} viewBox={`0 0 ${SVG_W} ${SVG_H}`} className="topology-svg"
          style={{width:"100%",maxWidth:SVG_W,height:"auto",display:"block",margin:"0 auto",cursor:isPanning?"grabbing":"grab"}}
          onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerLeave={onPointerUp} onDoubleClick={resetView}>
          <style>{`
            @keyframes topoDash{to{stroke-dashoffset:-20}}
            @keyframes topoSpin{to{transform:rotate(360deg)}}
            @keyframes topoPulse{0%,100%{transform:scale(1);opacity:.5}50%{transform:scale(1.35);opacity:.05}}
            .td{animation:topoDash 1s linear infinite}
            .ts{transform-box:fill-box;transform-origin:center;animation:topoSpin 2.4s linear infinite}
            .tp{transform-box:fill-box;transform-origin:center;animation:topoPulse 2.6s ease-in-out infinite}
          `}</style>
          <defs>
            <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="var(--border)" strokeWidth="0.3" opacity="0.3"/>
            </pattern>
          </defs>
          <rect width={SVG_W} height={SVG_H} fill="url(#grid)" />
          <g transform={`translate(${transform.x} ${transform.y}) scale(${transform.k})`}>
            {/* Zone outlines */}
            <rect x="10" y={ROOT_Y-ROOT_R-10} width={SVG_W-20} height={ROOT_R*2+20} rx="8" fill="none" stroke="var(--brand-accent)" strokeWidth="0.5" strokeDasharray="4,4" opacity="0.3"/>
            <rect x="10" y={CAT_Y-CAT_R-12} width={SVG_W-20} height={CAT_R*2+24} rx="8" fill="none" stroke="var(--border)" strokeWidth="0.5" strokeDasharray="3,3" opacity="0.3"/>
            <rect x="10" y={SPAWN_Y-SPAWN_R-10} width={SVG_W-20} height={SPAWN_R*2+20} rx="8" fill="none" stroke="var(--border)" strokeWidth="0.5" strokeDasharray="3,3" opacity="0.3"/>
            {/* Zone labels */}
            <text x="20" y={ROOT_Y-ROOT_R-14} fill="var(--text-faint)" fontSize="7" fontWeight="600" fontFamily="var(--font-manrope)" style={{textTransform:"uppercase",letterSpacing:"0.08em"}}>CIBLE</text>
            <text x="20" y={CAT_Y-CAT_R-16} fill="var(--text-faint)" fontSize="7" fontWeight="600" fontFamily="var(--font-manrope)" style={{textTransform:"uppercase",letterSpacing:"0.08em"}}>CATÉGORIES</text>
            <text x="20" y={SPAWN_Y-SPAWN_R-14} fill="var(--text-faint)" fontSize="7" fontWeight="600" fontFamily="var(--font-manrope)" style={{textTransform:"uppercase",letterSpacing:"0.08em"}}>ACTIFS DÉCOUVERTS</text>
            {/* Edges root→category */}
            {categoryNodes.map((cn,i)=>{
              const dim=hasFilter&&!catMatches(cn), hl=hoveredKey===cn.key||!!(hoveredKey&&catChildren.get(i)?.includes(hoveredKey));
              return <path key={`er-${cn.category}`} d={curvePath(SVG_W/2,ROOT_Y+ROOT_R,catX(i),CAT_Y-CAT_R)} fill="none"
                stroke={hl?"var(--brand-accent)":cn.color} strokeWidth={hl?2:1.5}
                strokeDasharray={cn.status==="completed"?undefined:"5,4"} className={cn.status==="running"?"td":""}
                opacity={dim?.15:1} style={{transition:"opacity 150ms ease,stroke 150ms ease"}} />;
            })}
            {/* Edges category→spawn */}
            {spawnedNodes.map((sn,si)=>{
              const cIdx=spawnParentCatIdx.get(sn.key); if(cIdx===undefined)return null;
              const dim=hasFilter&&!spawnMatches(sn), hl=hoveredKey===sn.key||hoveredKey===categoryNodes[cIdx]?.key;
              return <path key={`es-${sn.assetId}`} d={curvePath(catX(cIdx),CAT_Y+CAT_R,spawnX(si),SPAWN_Y-SPAWN_R)} fill="none"
                stroke={hl?"var(--brand-accent)":"var(--border)"} strokeWidth={hl?1.75:1} strokeDasharray="4,4"
                opacity={dim?.15:1} style={{transition:"opacity 150ms ease,stroke 150ms ease"}} />;
            })}
            {/* Root */}
            <g><circle cx={SVG_W/2} cy={ROOT_Y} r={ROOT_R+6} fill="none" stroke="var(--brand-accent)" strokeWidth="1.5" className="tp"/>
              <circle cx={SVG_W/2} cy={ROOT_Y} r={ROOT_R} fill="var(--panel)" stroke="var(--brand-accent)" strokeWidth="2.5"/>
              <text x={SVG_W/2} y={ROOT_Y+5} textAnchor="middle" fill="var(--text-primary)" fontSize="13" fontWeight="700">{assetEmoji(asset.asset_type)}</text></g>
            <text x={SVG_W/2} y={ROOT_Y+ROOT_R+16} textAnchor="middle" fill="var(--text-primary)" fontSize="11" fontWeight="600" fontFamily="var(--font-manrope)">{asset.value.length>22?asset.value.slice(0,22)+"…":asset.value}</text>
            {/* Category nodes */}
            {categoryNodes.map((cn,i)=>{
              const s=statusStroke(cn.status), dim=hasFilter&&!catMatches(cn), h=hoveredKey===cn.key;
              const childCount=catChildren.get(i)?.length??0;
              return <g key={cn.key} data-nocapture="true" style={{cursor:"pointer",opacity:dim?.25:1,transition:"opacity 150ms ease",pointerEvents:"auto"}}
                onClick={()=>onSelectCategory?.(cn.category)}
                onMouseEnter={e=>{setHoveredKey(cn.key);showTooltip(e,`${cn.emoji} ${cn.label}`,[`${cn.toolCount} outil(s) · ${cn.doneCount}/${cn.toolCount} terminés`,`Statut: ${statusFr(cn.status)}`,childCount?`${childCount} actif(s) découvert(s)`:"","Cliquer pour voir les résultats"].filter(Boolean),cn.color);}}
                onMouseLeave={()=>{setHoveredKey(null);setTooltip(null);}}>
                {cn.status==="running"&&<circle cx={catX(i)} cy={CAT_Y} r={CAT_R+5} fill="none" stroke={s} strokeWidth="1.5" strokeDasharray="3,5" className="ts"/>}
                <circle cx={catX(i)} cy={CAT_Y} r={h?CAT_R+3:CAT_R} fill={cn.bgColor} stroke={h?"var(--brand-accent)":cn.color} strokeWidth={h?2.5:2}/>
                <text x={catX(i)} y={CAT_Y+6} textAnchor="middle" fill="var(--text-primary)" fontSize="13" fontWeight="600">{cn.emoji}</text>
                <text x={catX(i)} y={CAT_Y+CAT_R+15} textAnchor="middle" fill={h?"var(--text-primary)":"var(--text-secondary)"} fontSize="9" fontWeight="500">{cn.label}</text>
                {/* Count badge */}
                <rect x={catX(i)+CAT_R-3} y={CAT_Y-CAT_R-6} width="18" height="11" rx="5" fill="var(--panel)" stroke="var(--border)" strokeWidth="0.5"/>
                <text x={catX(i)+CAT_R+6} y={CAT_Y-CAT_R+2} textAnchor="middle" fill="var(--text-primary)" fontSize="7" fontWeight="700">{cn.toolCount}</text>
                {/* Running indicator - cancel button hint */}
                {cn.status==="running"&&<text x={catX(i)} y={CAT_Y+CAT_R+25} textAnchor="middle" fill="var(--high)" fontSize="7" fontWeight="600">⏹ Cancel</text>}
              </g>;
            })}
            {/* Spawned nodes */}
            {spawnedNodes.map((sn,si)=>{
              const s=statusStroke(sn.status), f=statusFill(sn.status), dim=hasFilter&&!spawnMatches(sn), h=hoveredKey===sn.key;
              return <g key={sn.key} data-nocapture="true" style={{cursor:"pointer",opacity:dim?.25:1,transition:"opacity 150ms ease",pointerEvents:"auto"}}
                onClick={()=>onJumpToAsset(sn.assetId)}
                onMouseEnter={e=>{setHoveredKey(sn.key);showTooltip(e,`${sn.emoji} ${sn.value}`,[`Type: ${sn.type}`,`Statut: ${statusFr(sn.status)}`,sn.parentCategory?`Catégorie: ${categoryInfo(sn.parentCategory).label}`:"","Cliquer pour ouvrir cet actif"].filter(Boolean),s);}}
                onMouseLeave={()=>{setHoveredKey(null);setTooltip(null);}}>
                <circle cx={spawnX(si)} cy={SPAWN_Y} r={h?SPAWN_R+2:SPAWN_R} fill={f} stroke={h?"var(--brand-accent)":s} strokeWidth={h?2:1.5}/>
                <text x={spawnX(si)} y={SPAWN_Y+4} textAnchor="middle" fill="var(--text-secondary)" fontSize="9" fontWeight="600">{sn.emoji}</text>
                <text x={spawnX(si)} y={SPAWN_Y+SPAWN_R+12} textAnchor="middle" fill={h?"var(--text-primary)":"var(--text-secondary)"} fontSize="8" fontWeight="500">{sn.value.length>14?sn.value.slice(0,14)+"…":sn.value}</text>
              </g>;
            })}
          </g>
        </svg>
        {/* Tooltip */}
        {tooltip&&<div className="absolute z-20 px-2.5 py-2 rounded text-[10px] pointer-events-none"
          style={{left:tooltip.x,top:tooltip.y-10,transform:"translate(-50%,-100%)",background:"var(--panel)",border:`1px solid ${tooltip.accent}`,boxShadow:"0 4px 14px rgba(0,0,0,0.25)",minWidth:150,maxWidth:220}}>
          <p className="font-semibold mb-1" style={{color:"var(--text-primary)",fontSize:11}}>{tooltip.title}</p>
          {tooltip.lines.map((l,i)=><p key={i} style={{color:"var(--text-secondary)"}}>{l}</p>)}</div>}
      </div>
      {/* Legend + filters */}
      <div className="px-5 py-2.5 flex items-center gap-2 flex-wrap" style={{borderTop:"1px solid var(--border)"}}>
        <button onClick={()=>setStatusFilter("all")} className="text-[9px] px-2 py-1 rounded font-medium"
          style={{background:statusFilter==="all"?"var(--brand-accent)":"var(--panel-dim)",color:statusFilter==="all"?"#fff":"var(--text-secondary)",border:"1px solid var(--border)"}}>Tout</button>
        {filters.map(c=><button key={c.key} onClick={()=>setStatusFilter(f=>f===c.key?"all":c.key)} className="text-[9px] px-2 py-1 rounded font-medium flex items-center gap-1"
          style={{background:statusFilter===c.key?"var(--panel)":"transparent",border:`1px solid ${statusFilter===c.key?c.color:"var(--border)"}`,color:"var(--text-secondary)"}}>
          <span style={{width:6,height:6,borderRadius:2,background:c.color,display:"inline-block"}}/>{c.label}</button>)}
        {hasFilter&&<button onClick={()=>{setStatusFilter("all");setSearch("");}} className="text-[9px] px-2 py-1 rounded font-medium" style={{color:"var(--text-secondary)",textDecoration:"underline"}}>Réinitialiser</button>}
        <span className="text-[9px] ml-auto" style={{color:"var(--text-secondary)"}}>Molette zoom · Glisser déplacer · Double-clic reset</span>
      </div>
    </div>
  );
}
