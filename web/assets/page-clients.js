/* mon-clients page (spec §9.3): the registry as the panel's inbound table —
 * "⋯" for Edit / Revoke / Delete, a switch for Enabled, a filter by path
 * (a mon-client matches the paths its own paths expand into: hops matches
 * every probed hop), the full config error, the targets the box rejected
 * with their errors, the pairs the panel gave no AWG probe peer with the
 * panel's reason, and both revisions in the Edit modal. Target state is
 * deliberately absent: the panel's Monitoring page owns it. */
(function () {
  'use strict';

  var strings = {
    pathsHint: 'edges (the default) probes every edge front of the chain every cycle, active and standby, including edges that join later; ' +
      'direct and the inner hops are then held without probing — an inner hop is UP while an edge of its kind is UP. ' +
      'hops probes every hop of the chain every cycle, including hops that join later (both are proxy while the panel has no chain). ' +
      'Uncheck direct on boxes in hostile regions: it reveals the real server\'s address to that box. ' +
      'Uncheck hops to pick hops by name — an inner hop is not reachable from every region.',
    noHops: 'The panel has no probed hops right now.',
    reasons: {
      pool_exhausted: 'the AWG server\'s address pool is exhausted',
      limit: 'past the panel\'s monProbePeerLimit'
    },
    revokeWarning: 'The box gets 401 on its next call, wipes its state and sends a new registration request. Approve that request as a replacement to give it this id back. The registry row, its history and its paths stay.',
    deleteWarning: 'The row and its targets are removed for good. The panel drops its own copy on the next snapshot. A box that comes back gets a brand-new id.',
    nameRequired: 'Name is required.',
    pickPath: 'Pick at least one path.'
  };

  mon.start({
    data: function () {
      return {
        strings: strings,
        clients: [],
        chain: { hops: [], served: [] },
        pathFilter: undefined,
        edit: { open: false, client: null, name: '', region: '', paths: mon.picker(), busy: false },
        revoke: { open: false, client: null, busy: false },
        remove: { open: false, client: null, busy: false }
      };
    },
    computed: {
      filterOptions: function () {
        return (this.chain.served || []).map(function (p) { return { value: p, label: p }; });
      },
      shown: function () {
        var f = this.pathFilter;
        if (!f) { return this.clients; }
        return this.clients.filter(function (c) { return (c.probes || []).indexOf(f) >= 0; });
      }
    },
    mounted: function () { this.load(); },
    methods: {
      load: async function () {
        var env = await mon.api('GET', '/admin/api/clients');
        if (!env.success) { mon.notifyErr(env.msg); return; }
        this.clients = env.obj.clients || [];
        this.chain = env.obj.chain || { hops: [], served: [] };
        this.now = env.obj.now;
      },
      stateLabel: function (c) {
        if (!c.enabled) { return 'disabled'; }
        if (c.state === 'NEVER') { return 'never seen'; }
        return c.state;
      },
      stateClass: function (c) { return c.enabled ? c.state : 'DISABLED'; },
      hopOptions: function (named) { return mon.hopOptions(this.chain, named); },
      reasonText: function (reason) { return strings.reasons[reason] || reason; },
      unallocatedTitle: function (c) {
        var self = this;
        return (c.unallocated || []).map(function (u) { return u.path + ': ' + self.reasonText(u.reason); }).join('\n');
      },
      rejectedTitle: function (c) {
        return (c.rejectedTargets || []).map(function (r) { return r.target + ': ' + r.error; }).join('\n');
      },
      openEdit: function (c) {
        this.edit = {
          open: true,
          client: c,
          name: c.name,
          region: c.region,
          paths: mon.picker(c.paths),
          busy: false
        };
      },
      save: async function () {
        var e = this.edit;
        if (!e.name) { mon.notifyErr(strings.nameRequired); return; }
        var paths = mon.pickedPaths(e.paths);
        if (!paths.length) { mon.notifyErr(strings.pickPath); return; }

        e.busy = true;
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(e.client.id), {
          name: e.name, region: e.region, paths: paths
        });
        e.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.edit.open = false;
        this.load();
      },
      setEnabled: async function (c, enabled) {
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(c.id) + '/enabled', { enabled: enabled });
        if (!env.success) { mon.notifyErr(env.msg); this.load(); return; }
        mon.notifyOk(env.msg);
        this.load();
      },
      askRevoke: function (c) { this.revoke = { open: true, client: c, busy: false }; },
      doRevoke: async function () {
        this.revoke.busy = true;
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(this.revoke.client.id) + '/revoke');
        this.revoke.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.revoke.open = false;
        this.load();
      },
      askDelete: function (c) { this.remove = { open: true, client: c, busy: false }; },
      doDelete: async function () {
        this.remove.busy = true;
        var env = await mon.api('POST', '/admin/api/clients/' + encodeURIComponent(this.remove.client.id) + '/delete');
        this.remove.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.remove.open = false;
        this.load();
      }
    }
  });
})();
