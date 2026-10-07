"""Generate the desktop's linked toolkit and its integration backlog from one catalog."""
import html
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
with (ROOT / 'windows-crash-doctor/integrations/toolkit.tsv').open(encoding='utf-8', newline='') as source:
    data = list(csv.DictReader(source, delimiter='\t'))
for number, tool in enumerate(data, 101):
    tool['id'] = f'TK-{number:03}'
    tool['priority'] = ('P0' if tool['category'] in {'Windows graphical diagnostics', 'Crash dumps and drivers', 'Hardware inventory and sensors'}
                        else 'P2' if tool['category'] in {'Data erasure and ITAD', 'Remote support and MSP', 'Assets and monitoring', 'Identity, policy and security posture'}
                        else 'P1')
actions = json.loads((ROOT / 'windows-crash-doctor/integrations/toolkit-actions.json').read_text(encoding='utf-8'))
intro = ('The native desktop toolkit provides detection, configured launchers, selected diagnostic/action recipes '
         'and external report attachment. This checklist tracks the fuller tool-specific integrations still needed. '
         'Opening a website link does not install or run a tool. '
         'Review current vendor licensing before commercial use; no free-tier endpoint limits are assumed.')
md = ['# Windows Crash Doctor technician toolkit integration TODO', '', intro, '',
      '## Delivery order', '',
      'Implemented capabilities and verification: [TOOLKIT_IMPLEMENTATION.md](TOOLKIT_IMPLEMENTATION.md).', '',
      '- [x] TK-001: Add a categorized, searchable official-link catalog accessible from Integrations.',
      '- [ ] TK-002 [P0]: Detect installed tools and versions; show available, missing, unsupported and licence-review states.',
      '- [ ] TK-003 [P0]: Add user-selected launchers for installed tools with validated executable paths.',
      '- [ ] TK-004 [P0]: Add verified, opt-in installers with checksums, provenance and bounded failure handling.',
      '- [ ] TK-005 [P0]: Complete WinDbg/cdb symbol configuration and dump handoff; fix sensor path detection and PowerShell compatibility in shipped builds.',
      '- [ ] TK-006 [P1]: Import tool reports into a common evidence schema with timestamps, tool version, exit status and source paths.',
      '- [ ] TK-007 [P1]: Add repair workflows with exact command previews, privilege/reboot requirements, cancellation and before/after evidence.',
      '- [ ] TK-008 [P2]: Add bench intake, stress-test scheduling, boot-media instructions and external-result attachment.',
      '- [ ] TK-009 [P2]: Add separately authorized ITAD workflows with serial-number target verification and erasure certificates.',
      '- [ ] TK-010 [P2]: Add separately configured RMM/asset integrations with scoped credentials and privacy review.', '',
      '## Acceptance criteria', '',
      'For each unchecked entry: verify upstream availability and commercial/redistribution terms; implement the stated integration; '
      'document privilege, privacy and restart behavior; validate on Windows with unavailable-tool and failure cases. '
      'Existing partial collectors do not mean every listed capability is complete.', '',
      'Repair, erase, boot edits, registry changes, Driver Verifier, stress tests and remote actions require an explicit user-selected workflow. '
      'Recovery reads should preserve failing media; do not write recovered data to the source drive. '
      'Disk optimization must distinguish HDD defragmentation from SSD TRIM. '
      'File deletion or overwrite utilities do not establish SSD/NVMe sanitisation.', '',
      '## Licensing and availability notes', '',
      '- HWiNFO commercial use: review the upstream licence; do not label the freeware edition as an ongoing commercial entitlement.',
      '- [OCCT](https://www.ocbase.com/eula) and [AnyDesk](https://anydesk.com/en/commercial-use) restrict free use to personal/non-professional use.',
      '- [Memtest86+](https://www.memtest.org/) is GPL v2; distinguish it from PassMark MemTest86 and its edition terms.',
      '- [Macrium Reflect Free](https://www.macrium.com/product-support-policy) is retired; link to current Reflect editions rather than obsolete downloads.',
      '- Action1, Lansweeper, PRTG, Fing, NetSpot and other free/trial plans require a current terms check; no quota is promised here.',
      '- CCleaner, registry cleanup and privacy tweaks are optional external workflows; prefer built-in Storage Sense for routine Windows cleanup.',
      '- DBAN and Double Driver are legacy entries. TDSSKiller/Kaspersky tools and every security download require current availability and policy review.', '',
      '## Tool-by-tool backlog', '']
body = []
for category in dict.fromkeys(t['category'] for t in data):
    md += [f'### {category}', '']
    body += [f'<section><h2>{html.escape(category)}</h2>']
    for t in (t for t in data if t['category'] == category):
        definition = actions.get(t['name'], {})
        capabilities = ('Launcher detection + configured path' if definition.get('executables') else 'Instructions + configured external executable')
        if definition.get('actions'): capabilities += f"; {len(definition['actions'])} action(s)"
        capabilities += '; report attachment'
        md += [f"- [ ] **{t['id']} [{t['priority']}] [{t['name']}]({t['url']})** — {t['todo']}" + (f" Note: {t['note']}" if t['note'] else '') + f" Available now: {capabilities}."]
        search = html.escape(' '.join(str(v) for v in t.values()), quote=True)
        body += [f'<article data-search="{search}"><h3><a href="{html.escape(t["url"], quote=True)}" target="_blank" rel="noopener noreferrer">{html.escape(t["name"])}</a></h3>'
                 f'<p>{html.escape(t["todo"])}</p><p class="meta">{t["id"]} · {t["priority"]} · Further integration TODO</p><p>{html.escape(capabilities)}</p>'
                 + (f'<p class="note">{html.escape(t["note"])}</p>' if t['note'] else '') + '</article>']
    md += ['']
    body += ['</section>']
(ROOT / 'docs/TOOLKIT_INTEGRATION_TODO.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
page = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows Crash Doctor technician toolkit</title>
<style>body{font:16px system-ui,sans-serif;max-width:1050px;margin:30px auto;padding:0 20px;background:#f7f9fc;color:#17243a}h1{font-size:28px}a{color:#1754b8}input{font:inherit;padding:12px;width:calc(100% - 28px);border:1px solid #94a3b8;border-radius:6px}article{background:white;border:1px solid #dce3ed;border-radius:8px;padding:14px 20px;margin:10px 0}h3{margin:0}p{line-height:1.5}.meta{color:#52627a;font-size:13px}.note{color:#6b4e10}header{position:sticky;top:0;background:#f7f9fc;padding:10px 0}button{font:inherit;padding:8px}</style>
<h1>Windows Crash Doctor technician toolkit</h1><p>INTRO</p>
<p>Repair, erase, stress testing and remote workflows require separate user control. See each vendor for current commercial terms.</p>
<header><label for="search">Search tools, capabilities, categories or notes</label><input id="search" type="search" placeholder="e.g. RAM, WinDbg, network"><p id="count" role="status" aria-live="polite"></p></header>
BODY
<script>const input=document.getElementById('search');function filter(){let n=0;document.querySelectorAll('article').forEach(a=>{a.hidden=!a.dataset.search.toLowerCase().includes(input.value.toLowerCase());if(!a.hidden)n++});document.querySelectorAll('section').forEach(s=>s.hidden=![...s.querySelectorAll('article')].some(a=>!a.hidden));document.getElementById('count').textContent=n+' tools shown'}input.addEventListener('input',filter);filter();</script></html>'''
(ROOT / 'docs/TOOLKIT_CATALOG.html').write_text(page.replace('INTRO', html.escape(intro)).replace('BODY', '\n'.join(body)), encoding='utf-8')
print(f'Generated backlog and desktop catalog: {len(data)} tools.')
