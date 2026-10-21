import test from 'node:test';
import assert from 'node:assert/strict';

// Node 22.6+ strips TypeScript on import; older Node cannot load the mod file.
let mod = null;
try {
	mod = await import('../src/mod.ts');
} catch {
	mod = null;
}
const skip =
	mod && typeof mod.default === 'function'
		? false
		: 'mod.ts needs Node 22.6+ (type stripping)';

function setup({flags = {}, surface = false} = {}) {
	const recorded = {
		flags: {},
		commands: [],
		hooks: {},
		events: {},
		store: new Map(),
		state: new Map(),
		status: [],
		notices: [],
	};
	const cmd = {
		name: 'jev-guard',
		cwd: process.cwd(),
		addFlag: (name, definition) => {
			if (!(name in recorded.flags)) recorded.flags[name] = definition.default;
			return {dispose() {}};
		},
		getFlag: name => recorded.flags[name],
		addCommand: definition => {
			recorded.commands.push(definition);
			return {dispose() {}};
		},
		hooks: definitions => {
			Object.assign(recorded.hooks, definitions);
			return {dispose() {}};
		},
		on: (event, handler) => {
			recorded.events[event] = handler;
			return {dispose() {}};
		},
		store: {
			get: key => recorded.store.get(key),
			set: async (key, value) => {
				recorded.store.set(key, value);
			},
			delete: async key => {
				recorded.store.delete(key);
			},
		},
		state: {
			get: key => recorded.state.get(key),
			set: (key, value) => {
				recorded.state.set(key, value);
			},
		},
		ui: {
			notify: (message, level) => {
				recorded.notices.push({message, level});
			},
			confirm: async () => false,
			setStatus: text => {
				recorded.status.push(text);
			},
			capabilities: {status: true, surface},
		},
	};
	for (const [name, value] of Object.entries(flags))
		recorded.flags[name] = value;
	return {cmd, recorded};
}

test('the factory registers the whole surface', {skip}, () => {
	const {cmd, recorded} = setup({flags: {jevSweep: 'none'}});
	assert.doesNotThrow(() => mod.default(cmd));

	for (const hook of [
		'transformInput',
		'onPermissionRequest',
		'beforeToolCall',
		'afterToolCall',
		'onSessionStart',
		'onSessionEnd',
		'appendSystemPrompt',
	])
		assert.equal(typeof recorded.hooks[hook], 'function', hook);

	assert.equal(recorded.commands[0].name, 'jev-guard');
	assert.equal(typeof recorded.events.message_end, 'function');
	assert.equal(typeof recorded.hooks.appendSystemPrompt(), 'undefined');
});

test('mode off disables assessment', {skip}, async () => {
	const {cmd, recorded} = setup({
		flags: {jevMode: 'off', jevSweep: 'none'},
	});
	mod.default(cmd);
	assert.equal(
		await recorded.hooks.beforeToolCall({
			toolName: 'shell_command',
			input: {command: 'rm -rf /tmp/jev-demo'},
		}),
		undefined,
	);
});

test('read-only tools never reach Jev', {skip}, async () => {
	const {cmd, recorded} = setup({flags: {jevSweep: 'none'}});
	mod.default(cmd);

	assert.equal(
		await recorded.hooks.beforeToolCall({
			toolName: 'read_file',
			input: {absolute_path: '/tmp/a.ts'},
		}),
		undefined,
	);
	assert.equal(
		await recorded.hooks.onPermissionRequest({
			toolName: 'glob',
			input: {pattern: '**/*.ts'},
		}),
		undefined,
	);
	assert.equal(
		await recorded.hooks.afterToolCall({
			toolName: 'write_file',
			input: {file_path: '/tmp/a.ts'},
			result: 'x'.repeat(400),
		}),
		undefined,
	);
});

test('/jev-guard status, doctor, mode and clear work offline', {skip}, async () => {
	const {cmd, recorded} = setup({flags: {jevSweep: 'none'}});
	mod.default(cmd);
	const command = recorded.commands[0];

	const status = await command.handler({args: 'status'});
	assert.match(status.message, /jev-guard · mode auto/);
	assert.match(status.message, /thresholds:/);
	assert.match(status.message, /backend:/);

	const doctor = await command.handler({args: 'doctor'});
	assert.match(doctor.message, /native hooks/);
	assert.match(doctor.message, /scan cache:/);

	const mode = await command.handler({args: 'mode deny-only'});
	assert.match(mode.message, /deny-only/);
	assert.equal(recorded.state.get('mode'), 'deny-only');

	const badMode = await command.handler({args: 'mode nonsense'});
	assert.match(badMode.message, /usage:/);

	const cleared = await command.handler({args: 'clear'});
	assert.match(cleared.message, /cleared/);
});

test('session start resets state without throwing', {skip}, async () => {
	const {cmd, recorded} = setup({flags: {jevSweep: 'none'}});
	mod.default(cmd);
	await assert.doesNotReject(async () =>
		recorded.hooks.onSessionStart({source: 'startup'}),
	);
	await assert.doesNotReject(async () => recorded.hooks.onSessionEnd());
	assert.equal(recorded.status.at(-1), null);
});
