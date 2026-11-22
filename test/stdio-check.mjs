// Reads a recorded stdio session and asserts the protocol surface held up.
// Record one with (PowerShell/cmd redirection, not a piped child process):
//   cmd /c "node server.mjs < test\fixtures\stdio-requests.jsonl > test\fixtures\stdio-responses.jsonl"
import { readFileSync } from 'node:fs';

const file = process.argv[2] ?? 'test/fixtures/stdio-responses.jsonl';
const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);

let failed = 0;
const bad = (msg) => {
  failed++;
  console.log(`FAIL  ${msg}`);
};

const byId = new Map();
for (const line of lines) {
  let m;
  try {
    m = JSON.parse(line);
  } catch {
    bad(`malformed JSON line: ${line.slice(0, 100)}`);
    continue;
  }
  if (m.id !== undefined && m.id !== null) byId.set(m.id, m);
}

const init = byId.get(1);
if (!init?.result?.protocolVersion) bad('#1 no initialize result');
else console.log(`ok    initialize -> ${init.result.protocolVersion} (${init.result.serverInfo?.name}@${init.result.serverInfo?.version})`);

const tools = byId.get(2)?.result?.tools;
if (!Array.isArray(tools) || tools.length === 0) bad('#2 no tools');
else console.log(`ok    tools/list -> ${tools.length}: ${tools.map((t) => t.name).join(', ')}`);

const located = byId.get(3)?.result;
if (!located?.structuredContent?.confidence) bad('#3 locate_model returned no card');
else {
  const c = located.structuredContent;
  console.log(`ok    locate_model(W7) -> ${c.subject?.publisher} / ${c.confidence} / precision ${c.location?.precision}`);
}

const rules = byId.get(4)?.result?.structuredContent;
if (!rules?.rules?.includes('Precedence')) bad('#4 explain_rules missing precedence');
else console.log('ok    explain_rules');

const refused = byId.get(5)?.result;
const refusal = refused?.structuredContent;
if (refusal?.error !== 'NOT_ENTITLED') bad(`#5 entitlement gate did not refuse (got ${refusal?.error})`);
else console.log('ok    entitlement gate refused a stranger host');

const unknown = byId.get(6)?.result?.structuredContent;
if (unknown?.error !== 'UNKNOWN_TOOL') bad(`#6 unknown tool not reported (got ${unknown?.error})`);
else console.log('ok    unknown tool reported cleanly');

console.log(`\n${byId.size} responses, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
