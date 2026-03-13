import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, StylesheetJson } from 'cytoscape';
import { GitBranch } from 'lucide-react';
import type { Device, GraphEnrichment } from '../types/contracts';

// ── Risk score → node colour ─────────────────────────────────────────────
function nodeColor(risk: number): string {
  if (risk >= 80) return '#ef4444';
  if (risk >= 60) return '#f97316';
  if (risk >= 40) return '#eab308';
  if (risk >= 20) return '#22c55e';
  return '#3b82f6';
}

// ── Build cytoscape elements ─────────────────────────────────────────────
function buildElements(
  devices: Device[],
  enrichment: GraphEnrichment,
  attackPath: string[],
): ElementDefinition[] {
  const nodeIds = new Set(devices.map((d) => d.device_id));

  // Ensure all devices mentioned in enrichment exist as nodes
  const extraIds: string[] = [
    enrichment.source_device,
    ...enrichment.neighbors,
    ...enrichment.attack_paths.flat(),
    ...enrichment.next_target_prediction.map((n) => n.device_id),
  ].filter((id) => !nodeIds.has(id));

  extraIds.forEach((id) => nodeIds.add(id));

  // Nodes
  const nodes: ElementDefinition[] = Array.from(nodeIds).map((id) => {
    const d = devices.find((x) => x.device_id === id);
    const risk = d?.risk_score ?? 20;
    return {
      data: {
        id,
        label: id,
        risk,
        colour: nodeColor(risk),
        inPath: attackPath.includes(id),
      },
    };
  });

  // Edges: source → each neighbor
  const edges: ElementDefinition[] = enrichment.neighbors.map((n, i) => ({
    data: {
      id: `e-${enrichment.source_device}-${n}-${i}`,
      source: enrichment.source_device,
      target: n,
      suspicious: attackPath.includes(n) || enrichment.source_device === attackPath[0],
    },
  }));

  // Attack path chain edges
  for (let i = 0; i < attackPath.length - 1; i++) {
    const edgeId = `e-ap-${attackPath[i]}-${attackPath[i + 1]}`;
    const exists = edges.some((e) => e.data?.id === edgeId);
    if (!exists) {
      edges.push({
        data: { id: edgeId, source: attackPath[i], target: attackPath[i + 1], suspicious: true },
      });
    }
  }

  return [...nodes, ...edges];
}

// ── Cytoscape stylesheet ─────────────────────────────────────────────────
const CY_STYLE: StylesheetJson = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(colour)',
      'label': 'data(label)',
      'color': '#f4f4f5',
      'font-size': 10,
      'text-valign': 'bottom',
      'text-margin-y': 5,
      'font-family': 'Inter, sans-serif',
      'width': 32,
      'height': 32,
      'border-width': 2,
      'border-color': '#1a1a1f',
      'text-outline-width': 2,
      'text-outline-color': '#09090b',
    },
  },
  {
    selector: 'node[?inPath]',
    style: {
      'border-color': '#ef4444',
      'border-width': 3,
      'width': 40,
      'height': 40,
    },
  },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': 'rgba(99,102,241,0.35)',
      'target-arrow-color': 'rgba(99,102,241,0.35)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'opacity': 0.7,
    },
  },
  {
    selector: 'edge[?suspicious]',
    style: {
      'line-color': '#ef4444',
      'target-arrow-color': '#ef4444',
      'width': 2.5,
      'opacity': 1,
      'line-style': 'dashed',
      'line-dash-pattern': [6, 3],
    },
  },
  {
    selector: 'edge.path-visited',
    style: {
      'line-color': '#f97316',
      'target-arrow-color': '#f97316',
      'width': 3,
      'opacity': 1,
      'line-style': 'solid',
    },
  },
  {
    selector: 'edge.path-step',
    style: {
      'line-color': '#f43f5e',
      'target-arrow-color': '#f43f5e',
      'width': 4,
      'opacity': 1,
      'line-style': 'solid',
    },
  },
  {
    selector: ':selected',
    style: { 'border-color': '#818cf8', 'border-width': 3 },
  },
];

// ── Component ────────────────────────────────────────────────────────────
interface ThreatGraphProps {
  devices: Device[];
  enrichment: GraphEnrichment | null;
  onNodeClick: (deviceId: string) => void;
}

export function ThreatGraph({ devices, enrichment, onNodeClick }: ThreatGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const animationTimersRef = useRef<number[]>([]);
  const lastAnimationKeyRef = useRef<string>('');

  const attackPath = enrichment?.attack_paths[0] ?? [];

  const clearAnimationTimers = () => {
    for (const timerId of animationTimersRef.current) {
      window.clearTimeout(timerId);
    }
    animationTimersRef.current = [];
  };

  const runAttackPathAnimation = (cy: Core, path: string[]) => {
    clearAnimationTimers();
    cy.edges().removeClass('path-step path-visited');

    if (path.length < 2) {
      return;
    }

    const stepMs = 300;
    for (let i = 0; i < path.length - 1; i++) {
      const source = path[i];
      const target = path[i + 1];

      const timerId = window.setTimeout(() => {
        const edge = cy.$(`edge[source = "${source}"][target = "${target}"]`).first();
        if (!edge.empty()) {
          edge.removeClass('path-visited');
          edge.addClass('path-step');
        }

        if (i > 0) {
          const prevSource = path[i - 1];
          const prevTarget = path[i];
          const prevEdge = cy.$(`edge[source = "${prevSource}"][target = "${prevTarget}"]`).first();
          if (!prevEdge.empty()) {
            prevEdge.removeClass('path-step');
            prevEdge.addClass('path-visited');
          }
        }
      }, i * stepMs);

      animationTimersRef.current.push(timerId);
    }

    const finalTimer = window.setTimeout(() => {
      const lastSource = path[path.length - 2];
      const lastTarget = path[path.length - 1];
      const lastEdge = cy.$(`edge[source = "${lastSource}"][target = "${lastTarget}"]`).first();
      if (!lastEdge.empty()) {
        lastEdge.removeClass('path-step');
        lastEdge.addClass('path-visited');
      }
    }, (path.length - 1) * stepMs);

    animationTimersRef.current.push(finalTimer);
  };

  useEffect(() => {
    if (!containerRef.current) return;

    const elements = enrichment ? buildElements(devices, enrichment, attackPath) : [];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: CY_STYLE,
      // ✅ Built-in cose layout — no external plugin needed
      layout: {
        name: 'cose',
        animate: true,
        randomize: false,
        padding: 40,
        nodeRepulsion: () => 8000,
        idealEdgeLength: () => 120,
        gravity: 1,
        numIter: 1000,
        fit: true,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      minZoom: 0.3,
      maxZoom: 3,
      wheelSensitivity: 0.25,
    });

    cy.on('tap', 'node', (evt) => {
      onNodeClick(evt.target.id() as string);
    });

    cyRef.current = cy;
    return () => {
      clearAnimationTimers();
      cy.destroy();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Update when data changes
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().remove();
    if (enrichment) {
      cy.add(buildElements(devices, enrichment, attackPath));
    }

    const layout = cy.layout({ name: 'cose', animate: true, padding: 40, fit: true });
    layout.run();

    const animationKey = `${enrichment?.timestamp ?? 'none'}|${attackPath.join('->')}`;
    if (animationKey !== lastAnimationKeyRef.current) {
      lastAnimationKeyRef.current = animationKey;
      const timerId = window.setTimeout(() => runAttackPathAnimation(cy, attackPath), 220);
      animationTimersRef.current.push(timerId);
    }
  }, [devices, enrichment]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => () => clearAnimationTimers(), []);

  const propagationPct = enrichment ? Math.round(enrichment.propagation_risk * 100) : null;

  return (
    <div className="panel" style={{ borderRight: 'none', flex: 1 }}>
      <div className="card-header">
        <GitBranch size={14} className="icon" />
        Threat Graph
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-secondary)', fontWeight: 400 }}>
          {propagationPct === null ? (
            'awaiting graph enrichment'
          ) : (
            <>
              propagation risk:{' '}
              <strong style={{ color: propagationPct >= 70 ? 'var(--risk-high)' : 'var(--risk-medium)' }}>
                {propagationPct}%
              </strong>
            </>
          )}
        </span>
      </div>

      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {/* Cytoscape canvas */}
        <div
          ref={containerRef}
          style={{ width: '100%', height: '100%', background: 'var(--bg-base)' }}
        />

        {!enrichment && (
          <div style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--text-muted)',
            fontSize: 12,
            pointerEvents: 'none',
            background: 'linear-gradient(to bottom, rgba(0,0,0,0.08), rgba(0,0,0,0.16))',
          }}>
            Waiting for graph enrichment from the backend pipeline.
          </div>
        )}

        {/* Attack path badge */}
        {enrichment && attackPath.length > 0 && (
          <div style={{
            position: 'absolute', top: 10, right: 12,
            background: 'rgba(239,68,68,0.12)',
            border: '1px solid rgba(239,68,68,0.4)',
            borderRadius: 8,
            padding: '5px 10px',
            fontSize: 11,
            color: 'var(--risk-critical)',
            backdropFilter: 'blur(8px)',
          }}>
            🔴 {attackPath.join(' → ')}
          </div>
        )}

        {/* Risk legend */}
        <div style={{
          position: 'absolute', bottom: 10, left: 10,
          background: 'rgba(9,9,11,0.85)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '8px 12px',
          fontSize: 11,
          backdropFilter: 'blur(8px)',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}>
          {[
            { color: '#ef4444', label: 'Critical ≥80' },
            { color: '#f97316', label: 'High ≥60' },
            { color: '#eab308', label: 'Medium ≥40' },
            { color: '#22c55e', label: 'Low ≥20' },
            { color: '#3b82f6', label: 'Normal' },
          ].map(({ color, label }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
              {label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
