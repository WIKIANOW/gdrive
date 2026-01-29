const _0xUti = {
    _fS: (_0xb) => {
        if (_0xb === 0) return '0 B';
        const _k = 1024, _s = ['B', 'KB', 'MB', 'GB', 'TB'];
        const _i = Math.floor(Math.log(_0xb) / Math.log(_k));
        return parseFloat((_0xb / Math.pow(_k, _i)).toFixed(2)) + ' ' + _s[_i];
    },
    _dF: (_e) => {
        if (!_e) return "";
        const _d = new Date(_e.endsWith('Z') ? _e : _e.replace(' ', 'T') + 'Z');
        return _d.toLocaleString('vi-VN', {timeZone: 'Asia/Ho_Chi_Minh', hourCycle: 'h23'}).replace(/,/g, '');
    }
};
window.showAlert = function(_t, _m, _d = 2000) {
    let _c = document.getElementById('\x61\x6c\x65\x72\x74\x2d\x63\x6f\x6e\x74\x61\x69\x6e\x65\x72'); // alert-container
    if (!_c) {
        _c = document.createElement('div');
        _c.id = '\x61\x6c\x65\x72\x74\x2d\x63\x6f\x6e\x74\x61\x69\x6e\x65\x72';
        _c.className = 'fixed top-4 right-4 z-[9999] flex flex-col gap-3 pointer-events-none';
        document.body.appendChild(_c);
    }
    const _cfg = {
        success: 'bg-emerald-500', error: 'bg-rose-500', info: 'bg-indigo-500'
    }[_t] || 'bg-indigo-500';
    const _a = document.createElement('div');
    _a.className = `flex items-center gap-3 px-4 py-3 rounded-2xl text-white shadow-2xl transition-all duration-500 ${_cfg}`;
    _a.innerHTML = `<div class="flex-1"><p class="text-[10px] font-bold uppercase opacity-80">${_t}</p><p class="text-sm font-medium">${_m}</p></div>`;
    _c.appendChild(_a);
    setTimeout(() => _a.remove(), _d);
};

async function api(_p, _o = {}) {
    const _h = { ..._o.headers };
    if (!(_o.body instanceof FormData)) _h['\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65'] = '\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e';
    const _r = await fetch(_p, { ..._o, headers: _h, credentials: '\x69\x6e\x63\x6c\x75\x64\x65' });
    if (_r.status === 401) {
        showAlert("error", "\x53\x65\x73\x73\x69\x6f\x6e\x20\x65\x78\x70\x69\x72\x65\x64\x21"); // Session expired!
        logout();
        throw new Error();
    }
    return _r;
}

window.logout = async () => {
    try { await fetch('\x2f\x61\x70\x69\x2f\x6c\x6f\x67\x6f\x75\x74', { credentials: '\x69\x6e\x63\x6c\x75\x64\x65' }); } catch (e) {}
    localStorage.clear();
    window.location.href = '\x2f\x6c\x6f\x67\x69\x6e'; // /login
};

async function loadData() {
    try {
        const _res = await api('\x2f\x61\x70\x69\x2f\x73\x65\x72\x76\x65\x72\x73'); // /api/servers
        const _data = await _res.json();
        const _accs = _data.accounts || [];
        const _list = document.getElementById('\x61\x63\x63\x6f\x75\x6e\x74\x4c\x69\x73\x74'); // accountList
        if (!_list) return;

        _list.innerHTML = _accs.map(_acc => {
            const _pct = ((_acc.used_space / _acc.total_space) * 100).toFixed(2);
            return `
                <div class="group relative bg-[#0f172a]/60 p-5 rounded-[2rem] border border-white/5">
                    <div class="flex items-center gap-3 mb-5">
                        <div class="w-10 h-10 rounded-2xl bg-indigo-500 flex items-center justify-center">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
                        </div>
                        <h4 class="font-bold text-sm text-indigo-100 truncate">${_acc.name}</h4>
                    </div>
                    <div class="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                        <div class="bg-indigo-500 h-full" style="width: ${_pct}%"></div>
                    </div>
                    <div class="flex justify-between text-[9px] mt-2 text-slate-500">
                        <span>${_0xUti._fS(_acc.used_space)}</span>
                        <span>${_0xUti._fS(_acc.total_space)}</span>
                    </div>
                </div>`;
        }).join('');
    } catch (_e) {
        console.error("\x4c\x6f\x61\x64\x45\x72\x72", _e);
    }
}
