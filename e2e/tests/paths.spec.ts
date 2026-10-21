import type { Locator } from '@playwright/test';
import { expect, fieldInput, registerClient, test } from '../fixtures/admin';

/** The <input> of an antd checkbox by data-testid, whichever element antd stamps it on (see fieldInput). */
function box(scope: Locator, testId: string): Locator {
  return scope.locator(`input[data-testid="${testId}"], [data-testid="${testId}"] input`).first();
}

// The paths vocabulary of mon-server.md §5.1 (decisions #61, #100): a
// mon-client probes direct, edges (every probed edge of the chain), hops
// (every probed hop; both are proxy while the panel has none) and hops by
// name. The Approve modal offers direct, edges and hops with edges — the
// default — checked (§9.2); the Edit modal shows hops a box names even when the
// chain no longer probes them, so saving does not drop them (§9.3). This
// harness has no panel behind mon-server, so no hop is probed and the path
// filter has nothing to offer; the chain-dependent parts (the hop list, the
// filter, "no peer") are covered by the Go handler tests.
test('approve with the default paths, then narrow a box to named hops', async ({ adminPage, request }) => {
  const hostname = `e2e-paths-${Date.now()}`;
  await registerClient(request, { hostname });

  await adminPage.goto('/admin/requests');
  const row = adminPage.getByTestId('request-row').filter({ hasText: hostname });
  await row.getByTestId('request-approve').click();
  const modal = adminPage.getByTestId('approve-modal');
  await expect(modal).toBeVisible();
  await expect(box(modal, 'approve-path-edges')).toBeChecked();
  await expect(box(modal, 'approve-path-direct')).not.toBeChecked();
  await expect(box(modal, 'approve-path-hops')).not.toBeChecked();

  // With hops unchecked the list of hops to name is open; with no panel
  // there are none. Checking hops closes it.
  await expect(modal.getByTestId('approve-path-hop-list')).toContainText('no probed hops');
  await box(modal, 'approve-path-hops').check();
  await expect(modal.getByTestId('approve-path-hop-list')).toHaveCount(0);
  await box(modal, 'approve-path-hops').uncheck();

  const name = `Paths ${Date.now()}`;
  await fieldInput(adminPage, 'approve-name').fill(name);
  await modal.getByTestId('approve-submit').click();
  await expect(adminPage.getByTestId('request-row').filter({ hasText: hostname })).toHaveCount(0);

  await adminPage.goto('/admin/clients');
  const client = adminPage.getByTestId('client-row').filter({ hasText: name });
  await expect(client.getByTestId('client-path')).toHaveText(['edges']);
  const id = await client.getAttribute('data-client-id');

  // Narrowed to named hops through the API (the chain that would offer
  // them in the picker is the panel's), the Edit modal still shows them —
  // as not probed now — and a save keeps them.
  const upd = await adminPage.request.post(`/admin/api/clients/${id}`, {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    data: { name, region: '', paths: ['edge:edge-a', 'inner:core-1'] },
  });
  expect(upd.status(), await upd.text()).toBe(200);
  await adminPage.reload();
  await expect(client.getByTestId('client-path')).toHaveText(['edge:edge-a', 'inner:core-1']);

  await client.getByTestId('client-actions').click();
  await adminPage.getByTestId('client-edit').click();
  const edit = adminPage.getByTestId('edit-modal');
  await expect(box(edit, 'edit-path-direct')).not.toBeChecked();
  await expect(box(edit, 'edit-path-edges')).not.toBeChecked();
  await expect(box(edit, 'edit-path-hops')).not.toBeChecked();
  const named = edit.getByTestId('edit-path-hop');
  await expect(named).toHaveCount(2);
  await expect(named.first()).toContainText('edge:edge-a (not probed now)');
  await box(edit, 'edit-path-direct').check();
  await edit.getByTestId('edit-save').click();
  await expect(client.getByTestId('client-path')).toHaveText(['direct', 'edge:edge-a', 'inner:core-1']);

  // proxy left the vocabulary: the API refuses it and names what is valid.
  const bad = await adminPage.request.post(`/admin/api/clients/${id}`, {
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    data: { name, region: '', paths: ['proxy'] },
  });
  expect(bad.status()).toBe(400);
  expect((await bad.json()).msg).toContain('hops');
});
