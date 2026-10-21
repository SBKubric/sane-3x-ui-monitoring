/* Requests page (spec §9.2): pending registration requests, the Approve
 * modal with its "New mon-client / Replace an existing one" switch, and
 * Reject. The pairing code is shown large and monospaced because the whole
 * point is comparing it against the box's own log before approving. */
(function () {
  'use strict';

  var strings = {
    approveTitle: 'Approve registration request',
    compareCode: "Compare the code with the box's log before approving.",
    pathsHint: 'edges (the default) probes every edge front of the chain every cycle, active and standby, including edges that join later; ' +
      'direct and the inner hops are then held without probing — an inner hop is UP while an edge of its kind is UP. ' +
      'hops probes every hop of the chain every cycle, including hops that join later (both are proxy while the panel has no chain). ' +
      'Uncheck direct on boxes in hostile regions: it reveals the real server\'s address to that box. ' +
      'Uncheck hops to pick hops by name — an inner hop is not reachable from every region.',
    noHops: 'The panel has no probed hops right now.',
    replaceHint: 'The replacement keeps the existing id, its history, name, region and paths; the old token is revoked on approve.',
    nameRequired: 'Name is required.',
    pickExisting: 'Pick the mon-client this box replaces.',
    pickPath: 'Pick at least one path.'
  };

  /* refreshMs keeps the countdown and the list honest without hammering the
   * server: a request lives five minutes (spec §6), so ten seconds is
   * plenty to notice one expiring or arriving. */
  var refreshMs = 10000;

  mon.start({
    data: function () {
      return {
        strings: strings,
        requests: [],
        clients: [],
        chain: { hops: [] },
        limits: { perIpPerMin: 1, pendingPerIp: 3, pendingGlobal: 20 },
        modal: { open: false, request: null, mode: 'new', name: '', region: '', paths: mon.picker(), existingId: null, busy: false }
      };
    },
    computed: {
      clientOptions: function () {
        return this.clients.map(function (c) {
          return { value: c.monClientId, label: c.monClientId + ' · ' + c.name + (c.region ? ' (' + c.region + ')' : '') };
        });
      }
    },
    mounted: function () {
      this.load();
      this.timer = setInterval(this.tick, 1000);
      this.poll = setInterval(this.load, refreshMs);
    },
    unmounted: function () {
      clearInterval(this.timer);
      clearInterval(this.poll);
    },
    methods: {
      tick: function () { this.now += 1000; },
      load: async function () {
        var env = await mon.api('GET', '/admin/api/requests');
        if (!env.success) { return; }
        this.requests = env.obj.pending || [];
        this.clients = env.obj.clients || [];
        this.chain = env.obj.chain || { hops: [] };
        this.limits = env.obj.limits || this.limits;
        this.now = env.obj.now;
        this.pending = this.requests.length;
      },
      hopOptions: function (named) { return mon.hopOptions(this.chain, named); },
      rowClass: function (r) { return r.suggestReplacement ? 'sel' : ''; },
      openApprove: function (r, mode) {
        this.modal = {
          open: true,
          request: r,
          mode: mode,
          name: '',
          region: '',
          paths: mon.picker(),
          existingId: r.suggestReplacement ? r.suggestReplacement.monClientId : null,
          busy: false
        };
      },
      closeApprove: function () { this.modal.open = false; },
      approve: async function () {
        var m = this.modal;
        var body = { mode: m.mode };
        if (m.mode === 'new') {
          if (!m.name) { mon.notifyErr(strings.nameRequired); return; }
          var paths = mon.pickedPaths(m.paths);
          if (!paths.length) { mon.notifyErr(strings.pickPath); return; }
          body.name = m.name;
          body.region = m.region;
          body.paths = paths;
        } else {
          if (!m.existingId) { mon.notifyErr(strings.pickExisting); return; }
          body.existingId = m.existingId;
        }

        m.busy = true;
        var env = await mon.api('POST', '/admin/api/requests/' + encodeURIComponent(m.request.requestId) + '/approve', body);
        m.busy = false;
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.modal.open = false;
        this.load();
      },
      reject: async function (r) {
        var env = await mon.api('POST', '/admin/api/requests/' + encodeURIComponent(r.requestId) + '/reject');
        if (!env.success) { mon.notifyErr(env.msg); return; }
        mon.notifyOk(env.msg);
        this.load();
      }
    }
  });
})();
