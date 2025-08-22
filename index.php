<?php
require __DIR__ . '/utils.php';
require_login();
$c = cfg();
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>NetMon – Surveillance TCP</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <link rel="stylesheet" href="https://unpkg.com/@picocss/pico@2.0.6/css/pico.min.css">
  <style>
    body { padding: 1rem; }
    .muted { color:#777; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .chip { display:inline-block; padding:0.2rem 0.5rem; border-radius:0.5rem; background:#eef; margin-right:0.25rem;}
    .dir-in { color:#0a7; } .dir-out { color:#07a; }
    table td { vertical-align: top; }
  </style>
</head>
<body>
  <header>
    <h2>🔭 NetMon – TCP pour <span class="mono"><?=htmlspecialchars($c['TARGET_IP'])?></span></h2>
    <p class="muted">Surveillance temps réel (lab). <a href="logout.php">Se déconnecter</a></p>
  </header>

  <main>
    <section id="stats">
      <article>
        <h3>Statistiques</h3>
        <div id="statline" class="muted">Chargement…</div>
        <canvas id="chart" height="120"></canvas>
      </article>
    </section>

    <section id="filters">
      <article>
        <h3>Filtrer</h3>
        <form id="f">
          <label>Direction
            <select name="dir">
              <option value="all">Toutes</option>
              <option value="in">Entrant</option>
              <option value="out">Sortant</option>
            </select>
          </label>
          <label>Port
            <input type="number" name="port" placeholder="ex: 80" min="1" max="65535">
          </label>
          <label>IP contient
            <input type="text" name="search" placeholder="ex: 10.0.0.5">
          </label>
          <button type="submit">Appliquer</button>
          <button type="button" id="reset">Réinitialiser</button>
          <a class="secondary" id="exportCsv" href="#">Exporter CSV</a>
          <span class="muted" id="refresher"></span>
        </form>
      </article>
    </section>

    <section id="list">
      <article>
        <h3>Derniers évènements</h3>
        <div class="overflow-auto">
          <table>
            <thead>
              <tr>
                <th>Horodatage</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Flags</th>
                <th>Dir</th>
                <th>Meta</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
        </div>
        <nav>
          <ul id="pager"></ul>
        </nav>
      </article>
    </section>
  </main>

  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
  const qs = (s, p=document)=>p.querySelector(s);
  const qsa = (s, p=document)=>[...p.querySelectorAll(s)];

  let page=1, timer=null, lastStats=null;

  async function getJSON(url){
    const r = await fetch(url, {credentials:'same-origin'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  }

  async function loadStats(){
    const data = await getJSON('api.php?route=stats');
    lastStats = data;
    qs('#statline').textContent = `Total: ${data.total} | Dernier paquet: ${data.last ?? '—'} | Cible: ${data.target}`;
    // Graph top ports
    const labels = data.topPorts.map(x=>x.port);
    const values = data.topPorts.map(x=>x.cnt);
    const ctx = qs('#chart').getContext('2d');
    if(window._chart){ window._chart.destroy(); }
    window._chart = new Chart(ctx, {
      type:'bar',
      data:{ labels, datasets:[{label:'Occurrences', data:values, backgroundColor:'#7aa2ff'}]},
      options:{ plugins:{legend:{display:false}}, scales:{y:{beginAtZero:true}} }
    });
  }

  function currentQuery(){
    const f = new FormData(qs('#f'));
    const dir = f.get('dir') || 'all';
    const port = f.get('port') || '';
    const search = f.get('search') || '';
    return {dir, port, search};
  }

  function toQuery(q){ return new URLSearchParams(q).toString(); }

  async function loadList(){
    const q = currentQuery();
    const url = `api.php?route=list&page=${page}&` + toQuery(q);
    const data = await getJSON(url);
    const tbody = qs('#rows');
    tbody.innerHTML = '';
    data.rows.forEach(r=>{
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono">${r.ts}</td>
        <td class="mono">${r.src_ip}:${r.src_port}</td>
        <td class="mono">${r.dst_ip}:${r.dst_port}</td>
        <td>${r.tcp_flags ? `<span class="chip">${r.tcp_flags}</span>` : ''}</td>
        <td class="${r.direction==='in'?'dir-in':'dir-out'}">${r.direction}</td>
        <td class="muted mono">len=${r.len ?? '-'} win=${r.win ?? '-'}</td>
      `;
      tbody.appendChild(tr);
    });
    // Pager
    const totalPages = Math.max(1, Math.ceil(data.count / data.pageSize));
    const ul = qs('#pager'); ul.innerHTML='';
    const mk = (p, label)=>`<li><a href="#" data-p="${p}" ${p===page?'aria-current="page"':''}>${label}</a></li>`;
    ul.innerHTML = mk(1,'«') + mk(Math.max(1,page-1),'‹') +
                   mk(page, page.toString()) +
                   mk(Math.min(totalPages,page+1),'›') + mk(totalPages,'»');
    qsa('#pager a').forEach(a=>a.addEventListener('click', e=>{
      e.preventDefault();
      page = parseInt(a.dataset.p,10);
      loadList();
    }));
    qs('#refresher').textContent = 'auto-refresh 5s';
  }

  function schedule(){
    clearInterval(timer);
    timer = setInterval(async ()=>{
      try { await loadList(); } catch(e){}
    }, 5000);
  }

  qs('#f').addEventListener('submit', e=>{
    e.preventDefault(); page=1; loadList();
  });
  qs('#reset').addEventListener('click', ()=>{
    qs('[name="dir"]').value='all';
    qs('[name="port"]').value='';
    qs('[name="search"]').value='';
    page=1; loadList();
  });
  qs('#exportCsv').addEventListener('click', e=>{
    e.preventDefault();
    const now = new Date();
    const from = new Date(now.getTime()-3600*1000).toISOString().slice(0,19).replace('T',' ');
    const to = now.toISOString().slice(0,19).replace('T',' ');
    window.location = 'api.php?route=export&from='+encodeURIComponent(from)+'&to='+encodeURIComponent(to);
  });

  (async function init(){
    try { await loadStats(); } catch(e){ console.error(e); }
    await loadList();
    schedule();
  })();
  </script>
</body>
</html>
