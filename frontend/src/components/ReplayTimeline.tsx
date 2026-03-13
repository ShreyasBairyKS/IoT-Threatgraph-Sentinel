import React, { useState } from 'react';
import { Play, Pause, SkipBack, SkipForward } from 'lucide-react';

export interface ReplayFrame {
  timestamp: string;
  label: string;
}

interface ReplayTimelineProps {
  frames: ReplayFrame[];
  currentIndex: number;
  onChange: (index: number) => void;
}

export function ReplayTimeline({ frames, currentIndex, onChange }: ReplayTimelineProps) {
  const [playing, setPlaying] = useState(false);
  const intervalRef = React.useRef<ReturnType<typeof setInterval> | null>(null);
  const indexRef = React.useRef(currentIndex);
  const frameCountRef = React.useRef(frames.length);

  React.useEffect(() => {
    indexRef.current = currentIndex;
  }, [currentIndex]);

  React.useEffect(() => {
    frameCountRef.current = frames.length;
  }, [frames.length]);

  const play = () => {
    if (intervalRef.current) return;
    setPlaying(true);
    intervalRef.current = setInterval(() => {
      const maxIndex = Math.max(frameCountRef.current - 1, 0);
      const nextIndex = Math.min(indexRef.current + 1, maxIndex);
      onChange(nextIndex);
      if (nextIndex >= maxIndex) {
        pause();
      }
    }, 1200);
  };

  const pause = () => {
    setPlaying(false);
    if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null; }
  };

  React.useEffect(() => () => { if (intervalRef.current) clearInterval(intervalRef.current); }, []);

  const current = frames[currentIndex];

  return (
    <div style={{
      background: 'var(--bg-surface)',
      borderTop: '1px solid var(--border)',
      padding: '10px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: 14,
    }}>
      {/* Controls */}
      <button className="btn btn-ghost" onClick={() => onChange(0)} title="Reset"><SkipBack size={13} /></button>
      {playing
        ? <button className="btn btn-primary" onClick={pause}><Pause size={13} /> Pause</button>
        : <button className="btn btn-primary" onClick={play}><Play size={13} /> Replay</button>
      }
      <button className="btn btn-ghost" onClick={() => onChange(Math.min(currentIndex + 1, frames.length - 1))} title="Step forward"><SkipForward size={13} /></button>

      {/* Slider */}
      <div style={{ flex: 1 }}>
        <input
          type="range"
          min={0}
          max={frames.length - 1}
          value={currentIndex}
          onChange={(e) => { pause(); onChange(Number(e.target.value)); }}
        />
      </div>

      {/* Timestamp */}
      <div style={{ fontSize: 11, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
        {current ? (
          <>
            <span className="mono">{current.timestamp.slice(11, 19)}</span>
            {' · '}
            <span style={{ color: 'var(--text-muted)' }}>{current.label}</span>
          </>
        ) : '—'}
      </div>

      {/* Progress pill */}
      <div style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
        {currentIndex + 1} / {frames.length}
      </div>
    </div>
  );
}
