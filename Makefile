.PHONY: attack

## Runs every attack against the local stacks: NekoBet on :8081 and Yamesi on :8083
attack:
	node --test --test-reporter=spec 'attacks/*.test.mjs'
