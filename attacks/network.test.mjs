// The demos listen on loopback only: from this machine's own network addresses, every port is closed.
// Covers the Docker Compose stacks (ESC-09) and, when it is running, the OpsCircuit kind cluster (ESC-03).
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { networkInterfaces } from 'node:os';
import { describe, it } from 'node:test';

const PORTS = {
  8081: 'NekoBet web and API',
  8083: 'Yamesi web and API',
  9002: 'Yamesi object storage',
  8082: 'OpsCircuit: NekoBet web',
  3030: 'OpsCircuit: Grafana',
  9090: 'OpsCircuit: Prometheus',
};

const lanAddresses = Object.values(networkInterfaces())
  .flat()
  .filter((address) => address.family === 'IPv4' && !address.internal)
  .map((address) => address.address);

function isOpen(host, port) {
  return new Promise((resolve) => {
    const socket = connect({ host, port, timeout: 1500 });
    const done = (open) => {
      socket.destroy();
      resolve(open);
    };
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
  });
}

describe('network exposure', () => {
  it('has a network address to test from', () => {
    assert.ok(lanAddresses.length > 0, 'no non-loopback IPv4 address');
  });

  for (const [port, service] of Object.entries(PORTS)) {
    it(`does not expose ${service} (port ${port}) beyond loopback`, async () => {
      for (const host of lanAddresses) {
        assert.equal(await isOpen(host, Number(port)), false, `${service} answers on ${host}:${port}`);
      }
    });
  }
});
