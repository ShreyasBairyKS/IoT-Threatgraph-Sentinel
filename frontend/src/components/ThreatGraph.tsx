import { useEffect, useMemo, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Core, ElementDefinition, LayoutOptions, StylesheetJson } from 'cytoscape';
import { GitBranch, LocateFixed, ScanSearch } from 'lucide-react';
import type { Device, GraphEnrichment } from '../types/contracts';

function nodeColor(risk: number): string {
  if (risk >= 80) return '#ef4444';
  if (risk >= 60) return '#f97316';
  if (risk >= 40) return '#eab308';
  if (risk >= 20) return '#22c55e';
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
  const attackPaths = enrichment.attack_paths.length > 0
    ? enrichment.attack_paths
    : [[enrichment.source_device]];
  const attackPathNodes = new Set(attackPaths.flat());

  const relatedIds = new Set<string>([
    enrichment.source_device,
    ...enrichment.neighbors,
    ...attackPathNodes,
    ...enrichment.next_target_prediction.map((item) => item.device_id),
  ]);

  const sourceDevices = focusMode
    ? devices.filter((device) => relatedIds.has(device.device_id))
    : devices;

  const nodeIds = new Set(sourceDevices.map((device) => device.device_id));
  relatedIds.forEach((id) => nodeIds.add(id));

  const nodes: ElementDefinition[] = Array.from(nodeIds).map((id) => {
    const device = devices.find((item) => item.device_id === id);
    const risk = device?.risk_score ?? 18;
    return {
      data: {
        id,
        label: shortenLabel(id),
        fullLabel: id,
        risk,
        color: nodeColor(risk),
        inPath: attackPathNodes.has(id),
        isSource: enrichment.source_device === id,
        isHighlighted: highlightedDeviceId === id,
        size: Math.max(34, Math.min(60, 28 + risk / 3)),
      },
    };
  });

  const edges: ElementDefinition[] = enrichment.neighbors.map((neighbor, index) => ({
    data: {
      id: `edge-${enrichment.source_device}-${neighbor}-${index}`,
      source: enrichment.source_device,
      target: neighbor,
      suspicious: attackPathNodes.has(neighbor) || attackPathNodes.has(enrichment.source_device),
    },
  }));

  for (let index = 0; index < attackPaths.length; index += 1) {
    const path = attackPaths[index] ?? [];
    for (let step = 0; step < path.length - 1; step += 1) {
      const source = path[step];
      const target = path[step + 1];
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
      'font-size': 12,
      'font-weight': 700,
      'text-wrap': 'wrap',
      'text-max-width': '110px',
      'text-valign': 'center',
      'text-halign': 'center',
      'min-zoomed-font-size': 9,
      'border-width': 3,
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
      width: 3,
      'curve-style': 'bezier',
      'line-color': 'rgba(99, 102, 241, 0.6)',
      'target-arrow-color': 'rgba(99, 102, 241, 0.8)',
      'target-arrow-shape': 'triangle',
      opacity: 0.9,
      'arrow-scale': 1,
    },
  },
  {
    selector: 'edge[?suspicious]',
    style: {
      width: 4,
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
  const totalImpactedDevices = new Set([
    enrichment.source_device,
    ...enrichment.neighbors,
    ...enrichment.attack_paths.flat(),
  ]).size;
  const pathPreview = enrichment.attack_paths
    .slice(0, 2)
    .map((path) => path.map(shortenLabel).join(' → '))
    .join('  |  ');
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
    <div className="panel" style={{ borderRight: 'none', minHeight: 0, height: '100%', flex: 1 }}>
      <div className="card-header">
        <GitBranch size={14} className="icon" />
        {title}
        {subtitle && (
          <span style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 500 }}>
            {subtitle}
          </span>
        )}
        <span style={{ marginLeft: 'auto', fontSize: 13, color: 'var(--text-primary)', fontWeight: 700 }}>
          propagation risk{' '}
          <strong style={{ color: propagationPct >= 70 ? 'var(--risk-high)' : 'var(--risk-medium)' }}>
            {propagationPct}%
          </strong>
        </span>
      </div>

      <div style={{ flex: 1, minHeight: 260, height: '100%', position: 'relative', overflow: 'hidden', background: 'radial-gradient(circle at top, rgba(99,102,241,0.12), transparent 42%), var(--bg-base)' }}>
        <div
          ref={containerRef}
          style={{ width: '100%', height: '100%' }}
        />

        <div style={{ position: 'absolute', top: 12, left: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={() => cyRef.current?.fit(undefined, 30)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(9,9,11,0.9)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 999, padding: '7px 12px', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}
          >
            <LocateFixed size={13} /> Fit
          </button>
          <button
            onClick={() => cyRef.current?.layout(layout).run()}
            style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(9,9,11,0.9)', color: 'var(--text-primary)', border: '1px solid var(--border)', borderRadius: 999, padding: '7px 12px', fontSize: 13, fontWeight: 600, cursor: 'pointer' }}
          >
            <ScanSearch size={13} /> Re-layout
          </button>
        </div>

        {attackPath.length > 0 && (
          <div style={{ position: 'absolute', top: 12, right: 12, maxWidth: '62%', background: 'rgba(239,68,68,0.16)', border: '1px solid rgba(239,68,68,0.45)', borderRadius: 12, padding: '10px 12px', fontSize: 13, color: '#fecaca', backdropFilter: 'blur(10px)' }}>
            <div style={{ fontWeight: 700, marginBottom: 6 }}>Attack in progress</div>
            <div style={{ marginBottom: 4 }}>Source: <strong>{shortenLabel(enrichment.source_device)}</strong></div>
            <div style={{ marginBottom: 4 }}>Impacted devices: <strong>{totalImpactedDevices}</strong> · Paths: <strong>{enrichment.attack_paths.length}</strong></div>
            <div>Path(s): {pathPreview}</div>
          </div>
        )}

        <div style={{ position: 'absolute', bottom: 12, left: 12, background: 'rgba(9,9,11,0.92)', border: '1px solid var(--border)', borderRadius: 12, padding: '10px 12px', fontSize: 13, display: 'grid', gap: 6, color: 'var(--text-primary)' }}>
          {[
            { color: '#ef4444', label: 'Critical ≥80' },
            { color: '#f97316', label: 'High ≥60' },
            { color: '#eab308', label: 'Medium ≥40' },
            { color: '#22c55e', label: 'Low ≥20' },
            { color: '#3b82f6', label: 'Normal' },
          ].map((item) => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: '50%', background: item.color, display: 'inline-block' }} />
              {item.label}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
