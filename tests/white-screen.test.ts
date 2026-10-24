import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (p: string) => readFileSync(p, 'utf8');

describe('A render failure never blanks the Web Builder', () => {
  it('provides an error boundary with a recoverable message', () => {
    const ui = read('src/components/ui.tsx');
    assert.match(ui, /export class ErrorBoundary extends Component/);
    assert.match(ui, /getDerivedStateFromError/);
    assert.match(ui, /label: 'Try again', onClick: \(\) => this\.setState\(\{ failed: false \}\)/);
  });

  it('isolates every chat message so one bad reply keeps the conversation visible', () => {
    assert.match(read('src/components/builder/ChatPanel.tsx'), /<ErrorBoundary key=\{m\.id\} label="message" compact>\s*<ChatMessage /);
  });

  it('guards the whole builder and the AI settings panel', () => {
    const page = read('src/pages/WebBuilder.tsx');
    assert.match(page, /<ErrorBoundary label="Web Builder"><Workspace /);
    assert.match(page, /<ErrorBoundary label="Blackveil AI settings"><BlackveilAiPanel /);
  });

  it('renders empty or non-text replies and unknown file actions without throwing', () => {
    const msg = read('src/components/builder/ChatMessage.tsx');
    assert.match(msg, /typeof text === 'string' \? text : ''/);
    assert.match(msg, /No reply text\./);
    assert.match(msg, /ACTION\[f\.action\] \?\? ACTION\.update/);
    assert.match(msg, /String\(message\.content \?\? ''\)/);
  });
});
