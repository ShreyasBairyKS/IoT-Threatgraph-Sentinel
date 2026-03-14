import { useEffect, useMemo, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, LayoutOptions, StylesheetJson } from 'cytoscape';
import { GitBranch, LocateFixed, ScanSearch } from 'lucide-react';
import type { Device, GraphEnrichment } from '../types/contracts';

function nodeColor(device?: Device): string {
  if (!device) return '#3b82f6'; // normal
  if (device.status === 'critical') return '#ef4444';
  if (device.status === 'suspicious') return '#f97316';
  if (device.confidence === 'medium') return '#eab308';
  if (device.confidence === 'low' && device.status !== 'normal') return '#22c55e';
  return '#3b82f6';
}

function shortenLabel(label: string): string {
  if (label.length <= 14) return label;
  return `${label.slice(0, 6)}…${label.slice(-4)}`;
}

function buildElements(
  devices: Device[],
  enrichment: GraphEnrichment,
  focusMode: boolean,
  highlightedDeviceId?: string | null,
): ElementDefinition[] {
  const relatedIds = new Set<string>([
    enrichment.source_device,
    ...enrichment.neighbors,
    ...enrichment.attack_paths.flat(),
    ...enrichment.next_target_prediction.map((item) => item.device_id),
  ]);

  const sourceDevices = focusMode
    ? devices.filter((device) => relatedIds.has(device.device_id))
    : devices;

  const nodeIds = new Set(sourceDevices.map((device) => device.device_id));
  relatedIds.forEach((id) => nodeIds.add(id));

  const attackPath = enrichment.attack_paths[0] ?? [];
  const nodes: ElementDefinition[] = Array.from(nodeIds).map((id) => {
    const device = devices.find((item) => item.device_id === id);
    const risk = device?.risk_score ?? 18;
    return {
      data: {
        id,
        label: shortenLabel(id),
        fullLabel: id,
        risk,
        color: nodeColor(device),
        inPath: attackPath.includes(id),
        isSource: enrichment.source_device === id,
        isHighlighted: highlightedDeviceId === id,
        size: Math.max(28, Math.min(54, 24 + risk / 3)),
      },
    };
  });

  const edges: ElementDefinition[] = enrichment.neighbors.map((neighbor, index) => ({
    data: {
      id: `edge-${enrichment.source_device}-${neighbor}-${index}`,
      source: enrichment.source_device,
      target: neighbor,
      suspicious: attackPath.includes(neighbor) || enrichment.source_device === attackPath[0],
    },
  }));

  for (let index = 0; index < attackPath.length - 1; index += 1) {
    const source = attackPath[index];
    const target = attackPath[index + 1];
    const edgeId = `attack-${source}-${target}`;
    if (!edges.some((edge) => edge.data?.id === edgeId)) {
      edges.push({
        data: {
          id: edgeId,
          source,
          target,
          suspicious: true,
        },
      });
    }
  }

  return [...nodes, ...edges];
}

const GRAPH_STYLE: StylesheetJson = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      label: 'data(label)',
      width: 'data(size)',
      height: 'data(size)',
      color: '#f8fafc',
      'font-size': 9,
      'font-weight': 700,
      'text-wrap': 'wrap',
      'text-max-width': '70px',
      'text-valign': 'center',
      'text-halign': 'center',
      'min-zoomed-font-size': 7,
      'border-width': 2,
      'border-color': 'rgba(9, 9, 11, 0.95)',
      'overlay-opacity': 0,
       // Removed unsupported shadow style properties
       // 'shadow-blur': 14,
       // 'shadow-color': 'data(color)',
       // 'shadow-opacity': 0.26,
       // 'shadow-offset-x': 0,
       // 'shadow-offset-y': 0,
    },
  },
  {
    selector: 'node[?inPath]',
    style: {
      'border-color': '#fef08a',
      'border-width': 4,
    },
  },
  {
    selector: 'node[?isSource]',
    style: {
      'border-color': '#ffffff',
      'border-width': 4,
    },
  },
  {
    selector: 'node[?isHighlighted]',
    style: {
      'border-color': '#818cf8',
      'border-width': 5,
    },
  },
  {
    selector: 'edge',
    style: {
      width: 2,
      'curve-style': 'bezier',
      'line-color': 'rgba(99, 102, 241, 0.35)',
      'target-arrow-color': 'rgba(99, 102, 241, 0.45)',
      'target-arrow-shape': 'triangle',
      opacity: 0.72,
      'arrow-scale': 0.8,
    },
  },
  {
    selector: 'edge[?suspicious]',
    style: {
      width: 3,
      'line-color': '#fb7185',
      'target-arrow-color': '#fb7185',
      'line-style': 'dashed',
      'line-dash-pattern': [8, 5],
      opacity: 1,
    },
  },
  {
    selector: ':selected',
    style: {
      'border-color': '#38bdf8',
    },
  },
];

interface ThreatGraphProps {
  devices: Device[];
  enrichment: GraphEnrichment;
  onNodeClick: (deviceId: string) => void;
  title?: string;
  subtitle?: string;
  mode?: 'live' | 'focus';
  highlightedDeviceId?: string | null;
}

export function ThreatGraph({
  devices,
  enrichment,
  onNodeClick,
  title = 'Threat Graph',
  subtitle,
  mode = 'live',
  highlightedDeviceId,
}: ThreatGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const attackPath = enrichment.attack_paths[0] ?? [];
  const focusMode = mode === 'focus';

  const layout = useMemo<LayoutOptions>(() => (
    focusMode
      ? {
          name: 'breadthfirst',
          directed: true,
          padding: 28,
          spacingFactor: 1.2,
          animate: true,
          fit: true,
        }
      : {
          name: 'concentric',
          fit: true,
          padding: 36,
          animate: true,
          minNodeSpacing: 28,
          concentric: (node) => Number(node.data('risk')),
          levelWidth: () => 20,
        }
  ), [focusMode]);

  const elements = useMemo(
    () => buildElements(devices, enrichment, focusMode, highlightedDeviceId),
    [devices, enrichment, focusMode, highlightedDeviceId],
  );

  useEffect(() => {
    if (!containerRef.current) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: GRAPH_STYLE,
      layout,
      userZoomingEnabled: true,
      userPanningEnabled: true,
      minZoom: 0.5,
      maxZoom: 2.4,
      wheelSensitivity: 0.18,
      boxSelectionEnabled: false,
    });

    cy.on('tap', 'node', (event) => {
      onNodeClick(event.target.id() as string);
    });

    cyRef.current = cy;
    return () => cy.destroy();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().remove();
    cy.add(elements);
    cy.layout(layout).run();
  }, [elements, layout]);

  const propagationPct = Math.round(enrichment.propagation_risk * 100);

  return (
    <div className="panel" style={{ borderRight: 'none', minHeight: 0 }}>
      <div className="card-header">
        <GitBranch size={14} className="icon" />
        {title}
        {subtitle && (
          <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontWeight: 400 }}>
            {subtitle}
          </span>
        )}
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-secondary)', fontWeight: 500 }}>
          propagation risk{' '}
          <strong style={{ color: propagationPct >= 70 ? 'var(--risk-high)' : 'var(--risk-medium)' }}>
            {propagationPct}%
          </strong>
        </span>
      </div>

      <div style={{ flex: 1, minHeight: 0, position: 'relative', overflow: 'hidden', background: 'radial-gradient(circle at top, rgba(99,102,241,0.12), transparent 42%), var(--bg-base)' }}>
        <div
          ref={containerRef}
          style={{ width: '100%', height: '100%' }}
        />

        <div style={{ position: 'absolute', top: 12, left: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={() => cyRef.current?.fit(undefined, 30)}
            style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'rgba(9,9,11,0.82)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 999, padding: '4px 9px', fontSize: 11, cursor: 'pointer' }}
          >
            <LocateFixed size={11} /> Fit
          </button>
          <button
            onClick={() => cyRef.current?.layout(layout).run()}
            style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'rgba(9,9,11,0.82)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 999, padding: '4px 9px', fontSize: 11, cursor: 'pointer' }}
          >
            <ScanSearch size={11} /> Re-layout
          </button>
        </div>

        {attackPath.length > 0 && (
          <div style={{ position: 'absolute', top: 12, right: 12, maxWidth: '55%', background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.35)', borderRadius: 12, padding: '6px 10px', fontSize: 11, color: '#fca5a5', backdropFilter: 'blur(10px)' }}>
            Attack path: {attackPath.map(shortenLabel).join(' → ')}
          </div>
        )}

        <div style={{ position: 'absolute', bottom: 12, left: 12, background: 'rgba(9,9,11,0.82)', border: '1px solid var(--border)', borderRadius: 12, padding: '8px 10px', fontSize: 11, display: 'grid', gap: 4, color: 'var(--text-secondary)' }}>
          {[
            { color: '#ef4444', label: 'Critical ≥80' },
            { color: '#f97316', label: 'High ≥60' },
            { color: '#eab308', label: 'Medium ≥40' },
            { color: '#22c55e', label: 'Low ≥20' },
            { color: '#3b82f6', label: 'Normal' },
          ].map((item) => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: item.color, display: 'inline-block' }} />
              {item.label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
