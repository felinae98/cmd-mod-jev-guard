import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';

import {
	createScanCache,
	findInstructionFiles,
	projectRoots,
	scanFiles,
	scanInstructionsCached,
	userRoots,
} from '../src/scan.js';

async function withTempDir(run) {
	const root = mkdtempSync(join(tmpdir(), 'jev-scan-'));
	try {
		return await run(root);
	} finally {
		rmSync(root, {recursive: true, force: true});
	}
}

test('findInstructionFiles picks instruction docs and skips node_modules', async () => {
	await withTempDir(root => {
		writeFileSync(join(root, 'AGENTS.md'), '# agents\n');
		writeFileSync(join(root, 'notes.md'), '# notes\n');
		writeFileSync(join(root, 'index.ts'), 'export {};\n');
		mkdirSync(join(root, '.claude', 'rules'), {recursive: true});
		writeFileSync(join(root, '.claude', 'rules', 'one.md'), '# rule\n');
		mkdirSync(join(root, 'node_modules', 'evil'), {recursive: true});
		writeFileSync(join(root, 'node_modules', 'evil', 'SKILL.md'), '# evil\n');

		const files = findInstructionFiles([root]);
		assert.ok(files.some(file => file.endsWith('AGENTS.md')));
		assert.ok(files.some(file => file.endsWith(join('.claude', 'rules', 'one.md'))));
		assert.equal(files.some(file => file.includes('node_modules')), false);
		assert.equal(files.some(file => file.endsWith('notes.md')), false);
		assert.equal(files.some(file => file.endsWith('index.ts')), false);

		assert.deepEqual(findInstructionFiles([join(root, 'notes.md')]), [
			join(root, 'notes.md'),
		]);
	});
});

test('root lists cover Command Code locations', () => {
	assert.ok(projectRoots('/repo').includes(join('/repo', 'AGENTS.md')));
	assert.ok(projectRoots('/repo').includes(join('/repo', '.commandcode', 'skills')));
	assert.ok(userRoots('/home/u').includes(join('/home/u', '.agents')));
	assert.ok(userRoots('/home/u').includes(join('/home/u', '.commandcode', 'skills')));
});

test('the scan cache persists through the mod store', () => {
	const writes = [];
	const store = {
		get: () => undefined,
		set: async (key, value) => writes.push([key, value]),
	};
	const cache = createScanCache(store, {debounceMs: 60_000});
	assert.equal(cache.size(), 0);
	cache.put('abc', {kind: 'injection', p: 0.9});
	assert.equal(cache.size(), 1);
	assert.equal(cache.get('abc').kind, 'injection');
	cache.flush();
	assert.equal(writes.length, 1);
	assert.equal(writes[0][0], 'scanCache');
	assert.equal(writes[0][1].abc.kind, 'injection');
});

test('the scan cache reads what a previous session stored', () => {
	const cache = createScanCache(
		{
			get: () => ({abc: {kind: 'clean', p: 0.1, at: 1}}),
			set: async () => {},
		},
		{debounceMs: 60_000},
	);
	assert.equal(cache.get('abc').kind, 'clean');
});

const fakeFetch = (answers, requests) => async (_url, init) => {
	requests.push(JSON.parse(init.body));
	return {
		ok: true,
		status: 200,
		json: async () => ({answers}),
	};
};

const flaggingAnswers = {
	malicious: {noul: 0.99, confidence: 0.9},
	kind: {choice: 'exfiltration', confidence: 0.9},
};

test('scanInstructionsCached sends once, then serves the cached verdict', async () => {
	const requests = [];
	const fetchImpl = fakeFetch(flaggingAnswers, requests);
	const cache = createScanCache(undefined);
	const text = 'x'.repeat(300);
	const env = {JEV_API_KEY: 'test'};

	const first = await scanInstructionsCached(
		{text, source: 'AGENTS.md'},
		{env, fetchImpl},
		cache,
	);
	assert.equal(first.flagged, true);
	assert.equal(first.cached, false);

	const second = await scanInstructionsCached(
		{text, source: 'AGENTS.md'},
		{env, fetchImpl},
		cache,
	);
	assert.equal(second.flagged, true);
	assert.equal(second.cached, true);
	assert.equal(requests.length, 1);
});

test('a cached verdict is re-judged with the current threshold', async () => {
	const requests = [];
	const fetchImpl = fakeFetch(flaggingAnswers, requests);
	const cache = createScanCache(undefined);
	const text = 'x'.repeat(300);
	const source = 'AGENTS.md';

	await scanInstructionsCached(
		{text, source},
		{env: {JEV_API_KEY: 'test'}, fetchImpl},
		cache,
	);
	const relaxed = await scanInstructionsCached(
		{text, source},
		{
			env: {JEV_API_KEY: 'test', JEV_GUARD_SKILL_SERIOUS_P: '0.995'},
			fetchImpl,
		},
		cache,
	);
	assert.equal(relaxed.flagged, false);
	assert.equal(requests.length, 1);
});

test('scanFiles skips short files and reports flagged ones', () =>
	withTempDir(async root => {
		writeFileSync(join(root, 'short.md'), 'too short');
		writeFileSync(join(root, 'long.md'), 'x'.repeat(300));
		const requests = [];
		const results = await scanFiles(
			[join(root, 'short.md'), join(root, 'long.md')],
			{env: {JEV_API_KEY: 'test'}, fetchImpl: fakeFetch(flaggingAnswers, requests)},
			{concurrency: 2, cache: createScanCache(undefined)},
		);
		assert.equal(results.length, 1);
		assert.equal(results[0].file, join(root, 'long.md'));
		assert.equal(results[0].flagged, true);
	}));
