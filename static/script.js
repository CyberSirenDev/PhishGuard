// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(tab) {
    const isSingle = tab === 'single';
    document.getElementById('panelSingle').classList.toggle('hidden', !isSingle);
    document.getElementById('panelBulk').classList.toggle('hidden', isSingle);
    document.getElementById('tabSingle').classList.toggle('active', isSingle);
    document.getElementById('tabBulk').classList.toggle('active', !isSingle);
}


// ── Single Scan ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {

    // ── File label feedback ───────────────────────────────────────────────────
    document.getElementById('eml_file').addEventListener('change', (e) => {
        const name = e.target.files[0]?.name;
        const label = document.getElementById('emlLabel');
        const btn = e.target.closest('.upload-btn');
        label.textContent = name || 'Attach .eml';
        btn.classList.toggle('has-file', !!name);
    });

    // ── Form submit ───────────────────────────────────────────────────────────
    const form = document.getElementById('scanForm');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const spinner = analyzeBtn.querySelector('.spinner');
    const inputSec = document.getElementById('inputSection');
    const resultSec = document.getElementById('resultSection');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const url = document.getElementById('url').value.trim();
        const file = document.getElementById('eml_file').files[0] || null;
        const pdf = document.getElementById('generate_pdf').checked;

        if (!url && !file) { alert('Enter a URL or upload an .eml file.'); return; }

        setLoading(true);

        const fd = new FormData();
        fd.append('url', url);
        fd.append('email_text', '');
        fd.append('generate_pdf', pdf);
        if (file) fd.append('file', file);

        try {
            const resp = await fetch('/analyze', { method: 'POST', body: fd });
            const data = await resp.json();
            if (data.status === 'error') { alert(data.error); return; }
            showResults(data, url);
        } catch (err) {
            console.error(err);
            alert('Network error — is the server running?');
        } finally {
            setLoading(false);
        }
    });

    document.getElementById('newScanBtn').addEventListener('click', () => {
        resultSec.classList.add('hidden');
        inputSec.classList.remove('hidden');
        form.reset();
        const lbl = document.getElementById('emlLabel');
        lbl.textContent = 'Attach .eml';
        document.querySelector('#scanForm .upload-btn').classList.remove('has-file');
        resetRing();
        resetScreenshot();
    });

    function resetScreenshot() {
        // Cancel any pending screenshot timer
        if (window._screenshotTimer) {
            clearTimeout(window._screenshotTimer);
            window._screenshotTimer = null;
        }
        if (window._screenshotCountdown) {
            clearInterval(window._screenshotCountdown);
            window._screenshotCountdown = null;
        }
        // Reset screenshot panel to its default hidden state
        document.getElementById('screenshotPanel').classList.add('hidden');
        const img = document.getElementById('screenshotImg');
        img.src = '';
        img.classList.remove('ss-loaded');
        img.style.display = 'none';
        const skeleton = document.getElementById('screenshotSkeleton');
        if (skeleton) skeleton.style.display = 'flex';
        const countdown = document.getElementById('screenshotCountdown');
        if (countdown) countdown.textContent = '35';
        const errorBox = document.getElementById('screenshotError');
        if (errorBox) errorBox.classList.add('hidden');
        const countdownWrap = document.querySelector('.ss-countdown-wrap');
        if (countdownWrap) countdownWrap.style.display = '';
    }

    function setLoading(on) {
        btnText.textContent = on ? 'Analyzing…' : 'Analyze';
        spinner.classList.toggle('hidden', !on);
        analyzeBtn.disabled = on;
    }

    function resetRing() {
        document.getElementById('ringFill').style.strokeDashoffset = 213.6;
        document.getElementById('ringFill').style.stroke = 'var(--green)';
        document.getElementById('riskScore').textContent = '0';
    }

    // ── Render results ───────────────────────────────────────────────────────
    function showResults(data, url) {
        inputSec.classList.add('hidden');
        resultSec.classList.remove('hidden');
        resultSec.classList.add('fade-in');

        const score = data.risk_score || 0;

        // URL label
        document.getElementById('resultUrl').textContent = url || 'Email analysis';

        // Verdict badge
        const badge = document.getElementById('verdictBadge');
        badge.className = 'verdict';
        if (score >= 70) {
            badge.classList.add('v-phishing');
            badge.textContent = 'Phishing';
            document.getElementById('ringFill').style.stroke = 'var(--red)';
        } else if (score >= 40) {
            badge.classList.add('v-suspicious');
            badge.textContent = 'Suspicious';
            document.getElementById('ringFill').style.stroke = 'var(--yellow)';
        } else {
            badge.classList.add('v-safe');
            badge.textContent = 'Safe';
            document.getElementById('ringFill').style.stroke = 'var(--green)';
        }

        // Animate ring
        animateRing(score);

        // Insights
        const list = document.getElementById('insightsList');
        list.innerHTML = '';
        const items = data.details?.length ? data.details : ['No major indicators detected.'];
        items.forEach(t => {
            const li = document.createElement('li');
            li.textContent = t;
            list.appendChild(li);
        });

        // Feature tags
        const tags = document.getElementById('featureTags');
        tags.innerHTML = '';
        if (data.features) {
            Object.entries(data.features).forEach(([k, v]) => {
                const el = document.createElement('div');
                el.className = 'tag';
                el.textContent = `${k.replace(/_/g, ' ')}: ${v}`;
                tags.appendChild(el);
            });
        }

        // PDF button
        document.getElementById('pdfBtnSlot').innerHTML = '';
        if (data.report_url) {
            const a = document.createElement('a');
            a.href = data.report_url;
            a.target = '_blank';
            a.className = 'btn-ghost';
            a.textContent = '↓ PDF';
            document.getElementById('pdfBtnSlot').appendChild(a);
        }

        renderWhois(data.whois_data);
        renderSpfDmarc(data.spf_dmarc_data);
        renderSSL(data.ssl_data);
        renderRedirect(data.redirect_data);
        renderIntel(data.threat_intel);
    }

    function animateRing(target) {
        const circ = 213.6;
        const fill = document.getElementById('ringFill');
        const num = document.getElementById('riskScore');
        let cur = 0;
        const step = target / 50;
        const timer = setInterval(() => {
            cur = Math.min(cur + step, target);
            num.textContent = Math.round(cur);
            fill.style.strokeDashoffset = circ - (circ * cur / 100);
            if (cur >= target) clearInterval(timer);
        }, 18);
    }

    // ── SPF / DMARC Policy ────────────────────────────────────────────────────
    function renderSpfDmarc(sd) {
        const panel = document.getElementById('spfDmarcPanel');
        if (!sd || !sd.available) { panel.classList.add('hidden'); return; }
        panel.classList.remove('hidden');

        // Risk → CSS class mapping
        const riskClass = { low: 'eauth-low', medium: 'eauth-medium', high: 'eauth-high' };
        const badgeLabel = { low: 'Secure', medium: 'Weak', high: 'Missing' };

        // ── SPF ──
        const spf = sd.spf || {};
        document.getElementById('spfBadge').textContent = badgeLabel[spf.risk] || '?';
        document.getElementById('spfBadge').className =
            `eauth-badge ${riskClass[spf.risk] || 'eauth-high'}`;

        const spfRecordEl = document.getElementById('spfRecord');
        if (spf.record) {
            spfRecordEl.textContent = spf.record;
            spfRecordEl.style.display = 'block';
        } else {
            spfRecordEl.style.display = 'none';
        }
        document.getElementById('spfLabel').textContent = spf.risk_label || '';
        document.getElementById('spfLabel').className =
            `eauth-label eauth-label-${spf.risk || 'high'}`;

        // ── DMARC ──
        const dmarc = sd.dmarc || {};
        document.getElementById('dmarcBadge').textContent = badgeLabel[dmarc.risk] || '?';
        document.getElementById('dmarcBadge').className =
            `eauth-badge ${riskClass[dmarc.risk] || 'eauth-high'}`;

        const dmarcRecordEl = document.getElementById('dmarcRecord');
        if (dmarc.record) {
            dmarcRecordEl.textContent = dmarc.record;
            dmarcRecordEl.style.display = 'block';
        } else {
            dmarcRecordEl.style.display = 'none';
        }
        document.getElementById('dmarcLabel').textContent = dmarc.risk_label || '';
        document.getElementById('dmarcLabel').className =
            `eauth-label eauth-label-${dmarc.risk || 'high'}`;

        // DMARC metadata pills (policy, pct, reporting)
        const metaEl = document.getElementById('dmarcMeta');
        metaEl.innerHTML = '';
        if (dmarc.policy) {
            metaEl.innerHTML += `<span class="eauth-pill">Policy: <b>${dmarc.policy}</b></span>`;
        }
        if (dmarc.subdomain_policy) {
            metaEl.innerHTML += `<span class="eauth-pill">Subdomain: <b>${dmarc.subdomain_policy}</b></span>`;
        }
        if (dmarc.pct !== null && dmarc.pct !== undefined) {
            metaEl.innerHTML += `<span class="eauth-pill">Applied to: <b>${dmarc.pct}%</b> of mail</span>`;
        }
        if (dmarc.rua) {
            metaEl.innerHTML += `<span class="eauth-pill">Reports → <b>${dmarc.rua}</b></span>`;
        }
    }

    // ── WHOIS ─────────────────────────────────────────────────────────────────
    function renderWhois(w) {
        const panel = document.getElementById('whoisPanel');
        if (!w) { panel.classList.add('hidden'); return; }
        panel.classList.remove('hidden');

        const grid = document.getElementById('whoisGrid');
        const banner = document.getElementById('whoisBanner');
        grid.innerHTML = '';
        banner.className = 'whois-banner';

        const fields = [
            { label: 'Domain', value: w.domain },
            { label: 'Registrar', value: w.registrar },
            { label: 'Country', value: w.registrant_country },
            { label: 'Age', value: w.age_days >= 0 ? `${w.age_days}d` : 'Unknown' },
            { label: 'Created', value: w.creation_date },
            { label: 'Expires', value: w.expiry_date },
        ];

        fields.forEach(({ label, value }) => {
            const el = document.createElement('div');
            el.className = 'whois-field';
            el.innerHTML = `<div class="whois-field-label">${label}</div>
                            <div class="whois-field-value">${value || '—'}</div>`;
            grid.appendChild(el);
        });

        banner.classList.add(`risk-${w.age_risk || 'unknown'}`);
        banner.textContent = w.age_risk_label || 'Domain age unknown.';
    }

    // ── SSL ───────────────────────────────────────────────────────────────────
    function renderSSL(ssl) {
        const panel = document.getElementById('sslPanel');
        if (!ssl || !ssl.available) { panel.classList.add('hidden'); return; }
        panel.classList.remove('hidden');

        const grid = document.getElementById('sslGrid');
        const banner = document.getElementById('sslBanner');
        grid.innerHTML = '';
        banner.className = 'whois-banner';

        const fields = [
            { label: 'Issuer', value: ssl.issuer },
            { label: 'Expires On', value: ssl.expires_on },
            { label: 'Validity Period', value: `${ssl.validity_days} days` },
            { label: 'Cert Age', value: `${ssl.age_days} days` },
        ];

        fields.forEach(({ label, value }) => {
            const el = document.createElement('div');
            el.className = 'whois-field';
            el.innerHTML = `<div class="whois-field-label">${label}</div>
                            <div class="whois-field-value">${value || '—'}</div>`;
            grid.appendChild(el);
        });

        if (ssl.risk_score_penalty > 0) {
            banner.classList.add('risk-high');
            banner.innerHTML = `⚠️ <b>Certificate Risk Detected:</b><br/>` +
                ssl.risk_flags.map(f => `• ${f}`).join('<br/>');
        } else {
            banner.classList.add('risk-low');
            banner.textContent = '🟢 Valid SSL Certificate — Low Risk';
        }
    }

    // ── Redirect Chain ────────────────────────────────────────────────────────
    function renderRedirect(rd) {
        const panel = document.getElementById('redirectPanel');
        if (!rd || !rd.available || rd.hop_count <= 1) {
            panel.classList.add('hidden');
            return;
        }
        panel.classList.remove('hidden');

        const summary = document.getElementById('redirectSummary');
        const chain = document.getElementById('redirectChain');
        chain.innerHTML = '';
        summary.className = 'whois-banner';

        const hasRisk = rd.risk_score_penalty > 0;
        summary.classList.add(hasRisk ? 'risk-high' : 'risk-low');
        summary.innerHTML = hasRisk
            ? `⚠️ <b>${rd.hop_count} hops detected.</b> Cross-domain redirect → <code style="font-size:0.72rem">${rd.final_url}</code>`
            : `ℹ️ ${rd.hop_count} hops followed. Same-domain redirect — no additional risk.`;

        rd.chain.forEach(hop => {
            const isRedirect = [301, 302, 303, 307, 308].includes(hop.status);
            const isError = typeof hop.status === 'string';
            const crossed = hop.domain_changed;

            const dotClass = isError ? 'error' : isRedirect ? 'redirect' : 'ok';
            const badgeClass = isError ? 'badge-err' : isRedirect ? 'badge-3xx' : 'badge-2xx';

            const el = document.createElement('div');
            el.className = 'hop-entry';
            el.innerHTML = `
                <div class="hop-dot ${dotClass}">${hop.hop}</div>
                <div class="hop-body">
                    <div class="hop-url">${hop.url}</div>
                    <div class="hop-meta">
                        <span class="hop-badge ${badgeClass}">${hop.status}</span>
                        ${crossed ? '<span class="hop-badge badge-xdomain">Domain Changed</span>' : ''}
                        ${hop.note ? `<span>${hop.note}</span>` : ''}
                    </div>
                </div>`;
            chain.appendChild(el);
        });
    }

    // ── Threat Intel ──────────────────────────────────────────────────────────
    function renderIntel(intel) {
        const panel = document.getElementById('intelPanel');
        const ssPanel = document.getElementById('screenshotPanel');
        if (!intel) { panel.classList.add('hidden'); ssPanel.classList.add('hidden'); return; }
        panel.classList.remove('hidden');

        const grid = document.getElementById('intelGrid');
        grid.innerHTML = '';

        [
            { key: 'google_safe_browsing', label: 'Google Safe Browsing' },
            { key: 'virustotal', label: 'VirusTotal' },
            { key: 'urlscan', label: 'urlscan.io' },
        ].forEach(({ key, label }) => {
            const src = intel[key] || {};
            const card = document.createElement('div');
            card.className = 'intel-card';

            let meta = '';
            if (!src.available) {
                card.innerHTML = `<div class="intel-label">${label}</div>
                    <div class="intel-verdict" style="color:var(--text-3)">No key</div>`;
            } else {
                if (key === 'virustotal' && src.total_engines)
                    meta = `${src.malicious}/${src.total_engines} flagged`;
                else if (key === 'urlscan' && src.result_url)
                    meta = `<a href="${src.result_url}" target="_blank">Full report →</a>`;
                else if (src.threats?.length)
                    meta = src.threats.join(', ');

                card.innerHTML = `<div class="intel-label">${label}</div>
                    <div class="intel-verdict">${src.verdict || '—'}</div>
                    <div class="intel-meta">${meta}</div>`;
            }
            grid.appendChild(card);
        });

        // Screenshot — polished load experience with countdown + skeleton
        const us = intel['urlscan'] || {};
        if (us.available && us.screenshot_url) {
            ssPanel.classList.remove('hidden');

            const img      = document.getElementById('screenshotImg');
            const skeleton = document.getElementById('screenshotSkeleton');
            const countEl  = document.getElementById('screenshotCountdown');
            const errorBox = document.getElementById('screenshotError');
            const link     = document.getElementById('screenshotLink');

            // Reset to skeleton state
            img.style.display  = 'none';
            img.classList.remove('ss-loaded');
            img.src            = '';
            skeleton.style.display = 'flex';
            errorBox.classList.add('hidden');
            link.href = us.result_url || '#';

            // Live countdown — tick every second
            let secondsLeft = 35;
            countEl.textContent = secondsLeft;
            if (window._screenshotCountdown) clearInterval(window._screenshotCountdown);
            window._screenshotCountdown = setInterval(() => {
                secondsLeft = Math.max(0, secondsLeft - 1);
                countEl.textContent = secondsLeft;
                if (secondsLeft === 0) {
                    clearInterval(window._screenshotCountdown);
                    window._screenshotCountdown = null;
                }
            }, 1000);

            // Also wire the fallback link inside the error box
            const fallbackLink = document.getElementById('screenshotFallbackLink');
            if (fallbackLink) fallbackLink.href = us.result_url || '#';

            const countdownWrap = document.querySelector('.ss-countdown-wrap');

            // Load image after 35s
            if (window._screenshotTimer) clearTimeout(window._screenshotTimer);
            window._screenshotTimer = setTimeout(() => {
                const tempImg = new Image();
                tempImg.onload = () => {
                    skeleton.style.display = 'none';
                    if (countdownWrap) countdownWrap.style.display = 'none';
                    img.src = us.screenshot_url;
                    img.style.display = 'block';
                    requestAnimationFrame(() => img.classList.add('ss-loaded'));
                    clearInterval(window._screenshotCountdown);
                    window._screenshotCountdown = null;
                };
                tempImg.onerror = () => {
                    skeleton.style.display = 'none';
                    errorBox.classList.remove('hidden');
                    if (countdownWrap) countdownWrap.style.display = 'none';
                    clearInterval(window._screenshotCountdown);
                    window._screenshotCountdown = null;
                };
                tempImg.src = us.screenshot_url;
            }, 35000);
        } else {
            ssPanel.classList.add('hidden');
        }
    }

}); // end DOMContentLoaded (single)


// ── Bulk Scanner ──────────────────────────────────────────────────────────────
let bulkCache = [];
let sortAscMap = {};

document.addEventListener('DOMContentLoaded', () => {

    document.getElementById('bulkFile').addEventListener('change', (e) => {
        const name = e.target.files[0]?.name;
        document.getElementById('bulkFileLabel').textContent = name || 'Upload .txt / .csv';
        e.target.closest('.upload-btn').classList.toggle('has-file', !!name);
    });

    document.getElementById('bulkForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const textarea = document.getElementById('bulkUrls');
        const file = document.getElementById('bulkFile').files[0] || null;
        const btnTxt = document.getElementById('bulkBtnText');
        const spin = document.getElementById('bulkSpinner');
        const btn = document.getElementById('bulkBtn');

        if (!file && !textarea.value.trim()) { alert('Paste URLs or upload a file.'); return; }

        btnTxt.textContent = 'Scanning…';
        spin.classList.remove('hidden');
        btn.disabled = true;

        const fd = new FormData();
        fd.append('urls', textarea.value);
        if (file) fd.append('file', file);

        try {
            const resp = await fetch('/bulk-analyze', { method: 'POST', body: fd });
            const data = await resp.json();
            if (data.status === 'error') { alert(data.error); return; }
            bulkCache = data.results;
            renderBulkResults(data);
            const res = document.getElementById('bulkResultsSection');
            res.classList.remove('hidden');
            res.classList.add('fade-in');
            res.scrollIntoView({ behavior: 'smooth' });
        } catch (err) {
            console.error(err);
            alert('Network error.');
        } finally {
            btnTxt.textContent = 'Run Bulk Scan';
            spin.classList.add('hidden');
            btn.disabled = false;
        }
    });

    // Sortable headers
    document.querySelectorAll('#bulkTable th[data-col]').forEach(th => {
        th.addEventListener('click', () => {
            const col = th.dataset.col;
            sortAscMap[col] = !sortAscMap[col];
            const sorted = [...bulkCache].sort((a, b) => {
                const av = a[col] ?? '';
                const bv = b[col] ?? '';
                if (typeof av === 'number') return sortAscMap[col] ? av - bv : bv - av;
                return sortAscMap[col]
                    ? String(av).localeCompare(String(bv))
                    : String(bv).localeCompare(String(av));
            });
            renderRows(sorted);
        });
    });

    // CSV export
    document.getElementById('bulkExportBtn').addEventListener('click', async () => {
        const fd = new FormData();
        fd.append('urls', document.getElementById('bulkUrls').value);
        const resp = await fetch('/bulk-export', { method: 'POST', body: fd });
        const blob = await resp.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'phishguard_bulk.csv';
        a.click();
    });

});

function renderBulkResults(data) {
    document.getElementById('bulkSummary').innerHTML = `
        <div class="sum-item sum-total">
            <span class="sum-num">${data.total}</span>
            <span class="sum-label">Scanned</span>
        </div>
        <div class="sum-item sum-phishing">
            <span class="sum-num">${data.phishing}</span>
            <span class="sum-label">Phishing</span>
        </div>
        <div class="sum-item sum-suspicious">
            <span class="sum-num">${data.suspicious}</span>
            <span class="sum-label">Suspicious</span>
        </div>
        <div class="sum-item sum-safe">
            <span class="sum-num">${data.safe}</span>
            <span class="sum-label">Safe</span>
        </div>`;
    renderRows(data.results);
}

function renderRows(rows) {
    const tbody = document.getElementById('bulkTableBody');
    tbody.innerHTML = '';
    rows.forEach(r => {
        const sc = r.risk_score >= 70 ? 'score-high' : r.risk_score >= 40 ? 'score-mid' : 'score-low';
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${r.url}">${r.url}</td>
            <td class="${sc}">${r.risk_score < 0 ? '—' : r.risk_score}</td>
            <td><span class="pill pill-${r.verdict.toLowerCase()}">${r.verdict}</span></td>
            <td>${r.is_https ? '✓' : '✗'}</td>
            <td>${r.suspicious_keywords ?? '—'}</td>
            <td>${r.domain_entropy ?? '—'}</td>`;
        tbody.appendChild(tr);
    });
}
