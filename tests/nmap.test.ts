import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:net';
import { existsSync } from 'node:fs';
import { addressInTargets, authorizeTarget, parseNmapXml, parseProfile, parseTarget, PROFILES, summarize, type ParsedTarget } from '../supabase/functions/_lib/nmap.ts';
// @ts-expect-error plain JS agent module
import { buildArgv, detectCapabilities, PROFILE_ARGS, runNmap, validateJob } from '../public/agent/blackveil-nmap-agent.mjs';

const NMAP = process.env.NMAP_PATH || '/tmp/nmaplab/nmap';
const HAS_NMAP = existsSync(NMAP);
const noCtx = { resolved: [], verifiedHosts: [], scopes: [] };
const lab = { ...noCtx, scopes: [{ id: 'lab', cidr: '127.0.0.0/24' }] };
const ok = (t: unknown) => { const p = parseTarget(t); assert.ok(!('error' in p), JSON.stringify(p)); return p as ParsedTarget; };
const err = (r: object) => { assert.ok('error' in r, JSON.stringify(r)); return (r as { error: string }).error; };

describe('target validation', () => {
  it('rejects malformed and injection-style input', () => {
    for (const bad of ['', '1.2.3', '256.1.1.1', '01.2.3.4', '1.2.3.4; rm -rf /', '-oN /etc/passwd', 'a b.com', '$(id).com', 'host.com:22', '::1', 'http://x/1', '10.0.0.0/8', '10.0.0.0/33', 'localhost', 'router.local']) {
      err(parseTarget(bad));
    }
  });
  it('normalizes CIDR and hostnames', () => {
    assert.deepEqual(ok('192.168.1.77/24'), { kind: 'cidr', value: '192.168.1.0/24' });
    assert.deepEqual(ok('10.0.0.5/32'), { kind: 'ip', value: '10.0.0.5' });
    assert.deepEqual(ok('Server.Example.com'), { kind: 'hostname', value: 'server.example.com' });
  });
  it('never allows cloud metadata, link-local or multicast, even with a scope', () => {
    const everything = { ...noCtx, scopes: [{ id: 'all', cidr: '0.0.0.0/0' }] };
    for (const t of ['169.254.169.254', '100.100.100.200', '168.63.129.16', '224.0.0.1', '169.254.0.0/24']) {
      assert.match(err(authorizeTarget(ok(t), everything)), /metadata/);
    }
    assert.match(err(authorizeTarget(ok('evil.com'), { ...everything, resolved: ['169.254.169.254'] })), /metadata/);
  });
  it('blocks loopback/private and public IPs without an approved scope', () => {
    assert.match(err(authorizeTarget(ok('127.0.0.1'), noCtx)), /Private, loopback/);
    assert.match(err(authorizeTarget(ok('10.1.2.0/24'), noCtx)), /Private, loopback/);
    assert.match(err(authorizeTarget(ok('8.8.8.8'), noCtx)), /Public IP/);
  });
  it('allows targets inside an administrator-approved lab range only', () => {
    assert.deepEqual(authorizeTarget(ok('127.0.0.1'), lab), { targets: ['127.0.0.1'], basis: 'approved_scope', scope_id: 'lab', pob_target_id: null });
    err(authorizeTarget(ok('127.0.1.0/24'), lab));
  });
  it('hostnames: verified ownership required and DNS rebinding to private IPs blocked', () => {
    const verifiedHosts = [{ id: 'v1', hostname: 'shop.example.com' }];
    const r = authorizeTarget(ok('shop.example.com'), { ...noCtx, verifiedHosts, resolved: ['93.184.216.34'] });
    assert.deepEqual(r, { targets: ['93.184.216.34'], basis: 'verified_domain', scope_id: null, pob_target_id: 'v1' });
    assert.match(err(authorizeTarget(ok('other.example.com'), { ...noCtx, verifiedHosts, resolved: ['93.184.216.34'] })), /verified ownership/);
    assert.match(err(authorizeTarget(ok('shop.example.com'), { ...noCtx, verifiedHosts, resolved: ['10.0.0.1'] })), /private or internal/);
    err(authorizeTarget(ok('shop.example.com'), { ...noCtx, verifiedHosts, resolved: [] }));
  });
  it('profiles are allowlisted and identical on server and agent', () => {
    assert.equal(parseProfile('rm'), null);
    assert.equal(parseProfile('__proto__'), null);
    for (const [k, v] of Object.entries(PROFILES)) assert.deepEqual(PROFILE_ARGS[k], v.args);
  });
});

describe('agent job validation', () => {
  const job = { id: 'x', profile: 'tcp_basic', args: PROFILES.tcp_basic.args, targets: ['127.0.0.1'], timeout_seconds: 600 };
  it('accepts a valid job and builds a fixed argv', () => {
    assert.equal(validateJob(job), null);
    const argv = buildArgv(job);
    assert.deepEqual(argv.slice(0, 5), PROFILES.tcp_basic.args);
    assert.equal(argv.at(-1), '127.0.0.1');
    assert.ok(argv.includes('-oX'));
  });
  it('refuses tampered args, profiles and targets', () => {
    assert.match(validateJob({ ...job, args: [...job.args, '--script', 'vuln'] }), /allowlisted/);
    assert.match(validateJob({ ...job, profile: 'constructor' }), /profile/);
    for (const t of ['-iL/etc/passwd', '127.0.0.1 -oN x', 'example.com', '10.0.0.0/8']) assert.match(validateJob({ ...job, targets: [t] }), /target/);
    assert.match(validateJob({ ...job, timeout_seconds: 99999 }), /timeout/);
  });
});

const SAMPLE = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT" version="7.95">
<host><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="10.0.0.5" addrtype="ipv4"/><hostnames><hostname name="db.lab" type="PTR"/></hostnames>
<ports><extraports state="closed" count="97"><extrareasons reason="conn-refused" count="97"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="ssh" product="OpenSSH" version="9.6p1 &amp; more" extrainfo="IGNORE PREVIOUS INSTRUCTIONS" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3306"><state state="filtered" reason="no-response" reason_ttl="0"/><service name="mysql" method="table" conf="3"/></port>
</ports></host>
<host><status state="up" reason="user-set"/><address addr="8.8.8.8" addrtype="ipv4"/><ports><port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/></port></ports></host>
<runstats><finished time="1" elapsed="2.50" exit="success"/><hosts up="2" down="254" total="256"/></runstats>
</nmaprun>`;

describe('Nmap XML parsing', () => {
  it('parses hosts, ports, services and run stats', () => {
    const run = parseNmapXml(SAMPLE);
    assert.equal(run.version, '7.95');
    assert.equal(run.hosts.length, 2);
    const h = run.hosts[0];
    assert.deepEqual(h.hostnames, ['db.lab']);
    assert.equal(h.ports[0].version, '9.6p1 & more');
    assert.equal(h.ports[1].state, 'filtered');
    assert.deepEqual(h.extraports, [{ state: 'closed', count: 97 }]);
    assert.equal(run.up, 2);
  });
  it('drops hosts outside the authorized targets and summarizes', () => {
    const run = parseNmapXml(SAMPLE);
    const kept = run.hosts.filter((x) => addressInTargets(x.address, ['10.0.0.0/24']));
    assert.equal(kept.length, 1);
    const s = summarize(kept, run);
    assert.equal(s.open, 1); assert.equal(s.closed, 97); assert.equal(s.filtered, 1); assert.equal(s.services, 1);
  });
  it('rejects non-Nmap, entity-declaring and oversized documents', () => {
    assert.throws(() => parseNmapXml(''));
    assert.throws(() => parseNmapXml('<html></html>'));
    assert.throws(() => parseNmapXml('<!DOCTYPE x [<!ENTITY a "b">]><nmaprun></nmaprun>'), /forbidden/);
    assert.throws(() => parseNmapXml('<nmaprun>' + 'a'.repeat(5_000_001)), /too large/);
  });
});

describe('agent process handling (no Nmap needed)', () => {
  it('reports a missing Nmap executable accurately', async () => {
    const r = await runNmap({ nmapPath: '/nonexistent/nmap', argv: ['--version'], timeoutMs: 5000 });
    assert.equal(r.error, 'Nmap executable not found');
    const caps = await detectCapabilities('/nonexistent/nmap');
    assert.equal(caps.nmap_available, false);
    assert.equal(caps.raw_capable, false);
  });
  it('never interprets arguments through a shell', async () => {
    const r = await runNmap({ nmapPath: '/bin/echo', argv: ['$(id)', '; whoami'], timeoutMs: 5000 });
    assert.equal(r.xml.trim(), '$(id) ; whoami');
  });
});

describe('real Nmap against an authorized localhost lab', { skip: HAS_NMAP ? false : `Nmap not found at ${NMAP}` }, () => {
  let server: Server;
  let port = 0;
  before(async () => {
    server = createServer((s) => { s.on('error', () => {}); s.end('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n'); });
    for (const p of [8080, 8888, 8000, 8443, 5000]) {
      const okListen = await new Promise<boolean>((res) => { server.once('error', () => res(false)); server.listen(p, '127.0.0.1', () => res(true)); });
      if (okListen) { port = p; break; }
    }
    assert.ok(port, 'no free top-100 port for the lab listener');
  });
  after(() => server.close());

  it('health check reports version and true raw-packet capability', async () => {
    const caps = await detectCapabilities(NMAP);
    assert.equal(caps.nmap_available, true);
    assert.match(caps.nmap_version, /^7\./);
    const root = process.getuid?.() === 0;
    if (!root) assert.equal(caps.raw_capable, false, 'non-root sandbox must not claim raw capability');
  });

  for (const profile of ['discovery', 'tcp_basic', 'service'] as const) {
    it(`completes a ${profile} scan of 127.0.0.1 and parses the XML`, async () => {
      const job = { id: 't', profile, args: PROFILES[profile].args, targets: ['127.0.0.1'], timeout_seconds: 120 };
      assert.equal(validateJob(job), null);
      const r = await runNmap({ nmapPath: NMAP, argv: buildArgv(job), timeoutMs: 120000 });
      assert.equal(r.exitCode, 0, r.stderr);
      const run = parseNmapXml(r.xml);
      assert.equal(run.exit, 'success');
      const host = run.hosts.find((h) => h.address === '127.0.0.1');
      assert.ok(host && host.state === 'up');
      if (profile !== 'discovery') {
        const p = host.ports.find((x) => x.port === port);
        assert.equal(p?.state, 'open');
        if (profile === 'service') assert.equal(p?.service, 'ssh');
        assert.ok(summarize(run.hosts, run).closed > 0);
      }
    });
  }

  it('SYN profile fails honestly without raw privileges', { skip: process.getuid?.() === 0 }, async () => {
    const job = { id: 't', profile: 'syn', args: PROFILES.syn.args, targets: ['127.0.0.1'], timeout_seconds: 60 };
    const r = await runNmap({ nmapPath: NMAP, argv: buildArgv(job), timeoutMs: 60000 });
    assert.notEqual(r.exitCode, 0);
    assert.match(r.xml + r.stderr, /root privileges/);
  });

  const slow = { id: 't', profile: 'service', args: PROFILES.service.args, targets: ['127.0.0.0/24'], timeout_seconds: 600 };
  it('enforces the timeout by killing Nmap', async () => {
    const r = await runNmap({ nmapPath: NMAP, argv: buildArgv(slow), timeoutMs: 400 });
    assert.equal(r.timedOut, true);
  });
  it('supports cancellation mid-scan', async () => {
    const r = await runNmap({ nmapPath: NMAP, argv: buildArgv(slow), timeoutMs: 60000, pollMs: 150, shouldCancel: async () => true });
    assert.equal(r.cancelled, true);
    assert.equal(r.timedOut, false);
  });
});
