import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { parseTarGz, TarballService } from '../src/modules/registry/tarball.service.js';

function entry(name: string, body: string | Buffer = '', type = '0', prefix = ''): Buffer {
  const data = Buffer.from(body);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100);
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 12);
  header.fill(32, 148, 156);
  header.write(type, 156, 1);
  header.write('ustar\0', 257, 6);
  header.write(prefix, 345, 155);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8);
  return Buffer.concat([header, data, Buffer.alloc((512 - data.length % 512) % 512)]);
}

function archive(...entries: Buffer[]): Buffer {
  return gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));
}

function pax(path: string): string {
  const value = ` path=${path}\n`;
  let length = Buffer.byteLength(value) + 1;
  while (String(length).length + Buffer.byteLength(value) !== length) length = String(length).length + Buffer.byteLength(value);
  return `${length}${value}`;
}

test('parses regular files, ustar prefixes, PAX UTF-8 paths and GNU long names; skips links', () => {
  const long = `${'long/'.repeat(30)}source.js`;
  const unicode = `${'目录/'.repeat(40)}index.js`;
  const files = parseTarGz(archive(
    entry('index.js', 'export {};', '0', 'package/src'),
    entry('package/link.js', '', '2'),
    entry('package/PaxHeader', pax(`package/${unicode}`), 'x'),
    entry('package/short.js', 'pax'),
    entry('././@LongLink', `package/${long}\0`, 'L'),
    entry('package/short.js', 'gnu'),
    entry('package/directory', '', '5'),
  ));
  assert.deepEqual([...files.keys()], ['src/index.js', unicode, long]);
  assert.equal(Buffer.from(files.get(unicode)!).toString(), 'pax');
});

test('rejects traversal and absolute paths before stripping the package prefix', () => {
  for (const path of ['package/../escape', '../escape', '/package/escape', 'C:/package/escape', 'package/C:/escape', 'package\\..\\escape']) {
    assert.throws(() => parseTarGz(archive(entry(path))), /Unsafe tar path/);
  }
  assert.throws(() => parseTarGz(archive(entry('package/pax', pax('package/../escape'), 'x'), entry('package/file'))), /Unsafe/);
  assert.throws(() => parseTarGz(archive(entry('././@LongLink', '/absolute\0', 'L'))), /Unsafe/);
});

test('rejects malformed and truncated tar input', () => {
  const bad = entry('package/file', 'abc');
  bad[0] ^= 1;
  assert.throws(() => parseTarGz(archive(bad)), /checksum/);
  assert.throws(() => parseTarGz(gzipSync(entry('package/file', 'abc').subarray(0, 513))), /Truncated/);
  assert.throws(() => parseTarGz(archive(entry('package/pax', '999 path=x\n', 'x'))), /PAX/);
  assert.throws(() => parseTarGz(Buffer.from('not gzip')));
});

test('enforces compressed, extracted and file count caps (including duplicate names)', () => {
  assert.throws(() => parseTarGz(new Uint8Array(25 * 1024 * 1024 + 1)), /25 MB/);
  assert.throws(() => parseTarGz(archive(...Array.from({ length: 5001 }, () => entry('package/file')))), /5000 files/);
  assert.throws(() => parseTarGz(archive(entry('package/large', Buffer.alloc(60 * 1024 * 1024 + 1)))), /60 MB/);
});

test('fetchFiles rejects HTTP errors and streams with oversized declared or actual lengths', async t => {
  const original = globalThis.fetch;
  t.after(() => { globalThis.fetch = original; });
  const service = new TarballService();
  globalThis.fetch = async (_url, options) => {
    assert.ok(options?.signal instanceof AbortSignal);
    return new Response(archive(entry('package/index.js', 'benign')));
  };
  assert.equal((await service.fetchFiles('https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz')).size, 1);
  globalThis.fetch = async () => new Response(null, { status: 404 });
  await assert.rejects(service.fetchFiles('https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz'), /HTTP 404/);
  globalThis.fetch = async () => new Response('x', { headers: { 'content-length': String(26 * 1024 * 1024) } });
  await assert.rejects(service.fetchFiles('https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz'), /25 MB/);
  globalThis.fetch = async () => new Response(new Uint8Array(25 * 1024 * 1024 + 1));
  await assert.rejects(service.fetchFiles('https://registry.npmjs.org/fixture/-/fixture-1.0.0.tgz'), /25 MB/);
});

test('fetchFiles refuses tarballs outside the npm registry', async () => {
  await assert.rejects(new TarballService().fetchFiles('https://evil.example/x.tgz'), /Refusing/);
});
