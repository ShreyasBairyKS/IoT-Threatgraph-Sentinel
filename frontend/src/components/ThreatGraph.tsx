import { useEffect, useMemo, useRef } from 'react';
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
  activeNodeId: string | null,
): ElementDefinition[] {
  const nodeIds = new Set(devices.map((d) => d.device_id));

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
        isActive: id === activeNodeId,
      },
    };
  });

  // Source → neighbor edges
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
    if (!edges.some((e) => e.data?.id === edgeId)) {
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
      'transition-property': 'border-color, border-width, width, height',
      'transition-duration': '0.3s' as unknown as number,
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
    // Active replay node: bright indigo ring + bigger
    selector: 'node[?isActive]',
    style: {
      'border-color': '#818cf8',
      'border-width': 4,
      'width': 44,
      'height': 44,
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
      // Cytoscape does not support CSS animations; we animate via RAF below.
    },
  },
  {
    selector: ':selected',
    style: { 'border-color': '#818cf8', 'border-width': 3 },
  },
];

// ── Suspicious-edge marching-ants animation via requestAnimationFrame ────
let _animFrame: number | null = null;
let _dashOffset = 0;

function startEdgeAnimation(cy: Core) {
  if (_animFrame !== null) return;           // already running
  const step = () => {
    _dashOffset = (_dashOffset + 0.5) % 100;
    cy.edges('[?suspicious]').style({
      'line-dash-offset': -_dashOffset,
    } as Record<string, unknown>);
    _animFrame = requestAnimationFrame(step);
  };
  _animFrame = requestAnimationFrame(step);
}

function stopEdgeAnimation() {
  if (_animFrame !== null) {
    cancelAnimationFrame(_animFrame);
    _animFrame = null;
  }
}

// ── Component ────────────────────────────────────────────────────────────
interface ThreatGraphProps {
  devices: Device[];
  enrichment: GraphEnrichment;
  onNodeClick: (deviceId: string) => void;
  /** Device id to highlight as the currently replaying / clicked node. */
  activeNodeId?: string | null;
}

export function ThreatGraph({ devices, enrichment, onNodeClick, activeNodeId = null }: ThreatGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const attackPath = useMemo(() => enrichment.attack_paths[0] ?? [], [enrichment.attack_paths]);

  // ── Initial mount ──────────────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return;

    const elements = buildElements(devices, enrichment, attackPath, activeNodeId);

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: CY_STYLE,
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
    startEdgeAnimation(cy);

    return () => {
      stopEdgeAnimation();
      cy.destroy();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Update graph when enrichment / devices change ─────────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
    cy.add(buildElements(devices, enrichment, attackPath, activeNodeId));
    cy.layout({ name: 'cose', animate: true, padding: 40, fit: true }).run();
    // Restart the animation on the new suspicious edges
    stopEdgeAnimation();
    startEdgeAnimation(cy);
  }, [devices, enrichment]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Highlight active replay node without full rebuild ────────────────
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    // Clear all active flags
    cy.nodes().data('isActive', false);
    if (activeNodeId) {
      const node = cy.getElementById(activeNodeId);
      if (node.length) {
        node.data('isActive', true);
        // Flash style immediately
        node.style({
          'border-color': '#818cf8',
          'border-width': 4,
          'width': 44,
          'height': 44,
        });
        // Reset non-active nodes
        cy.nodes().not(node).style({
          'border-width': 2,
          'border-color': '#1a1a1f',
          'width': 32,
          'height': 32,
        });
        // Keep inPath styling for path nodes
        attackPath.forEach((id) => {
          const pn = cy.getElementById(id);
          if (pn.length && id !== activeNodeId) {
            pn.style({ 'border-color': '#ef4444', 'border-width': 3, 'width': 40, 'height': 40 });
          }
        });
      }
    }
  }, [activeNodeId, attackPath]);

  const propagationPct = Math.round(enrichment.propagation_risk * 100);

  return (
    <div className="panel" style={{ borderRight: 'none', flex: 1 }}>
      <div className="card-header">
        <GitBranch size={14} className="icon" />
        Threat Graph
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-secondary)', fontWeight: 400 }}>
          propagation risk:{' '}
          <strong style={{ color: propagationPct >= 70 ? 'var(--risk-high)' : 'var(--risk-medium)' }}>
            {propagationPct}%
          </strong>
        </span>
      </div>

      <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
        {/* Cytoscape canvas */}
        <div
          ref={containerRef}
          style={{ width: '100%', height: '100%', background: 'var(--bg-base)' }}
        />

        {/* Attack path badge */}
        {attackPath.length > 0 && (
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

        {/* Animation legend */}
        <div style={{
          position: 'absolute', bottom: 10, right: 12,
          background: 'rgba(9,9,11,0.85)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '6px 10px',
          fontSize: 10,
          backdropFilter: 'blur(8px)',
          color: 'var(--text-secondary)',
          display: 'flex',
          flexDirection: 'column',
          gap: 3,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ display: 'inline-block', width: 16, borderTop: '2px dashed #ef4444' }} />
            Suspicious edge
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%', border: '3px solid #818cf8', background: 'transparent' }} />
            Active node
          </div>
        </div>
      </div>
    </div>
  );
}
