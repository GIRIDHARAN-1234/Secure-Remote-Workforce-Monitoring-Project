const ImportExportPage = {
  load() {
    this.bindEvents();
  },

  bindEvents() {
    const dropZone = document.getElementById('import-drop-zone');
    const fileInput = document.getElementById('import-file-input');

    if (dropZone && fileInput) {
      dropZone.onclick = () => fileInput.click();

      dropZone.ondragover = (e) => {
        e.preventDefault();
        dropZone.classList.add('border-cyan-500', 'bg-cyan-950/20');
      };

      dropZone.ondragleave = () => {
        dropZone.classList.remove('border-cyan-500', 'bg-cyan-950/20');
      };

      dropZone.ondrop = async (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-cyan-500', 'bg-cyan-950/20');
        if (e.dataTransfer.files.length > 0) {
          await this.uploadFile(e.dataTransfer.files[0]);
        }
      };

      fileInput.onchange = async () => {
        if (fileInput.files.length > 0) {
          await this.uploadFile(fileInput.files[0]);
        }
      };
    }

    // Download template
    const templateBtn = document.getElementById('btn-download-template');
    if (templateBtn) {
      templateBtn.onclick = () => {
        window.location.href = '/api/v1/import-export/template';
      };
    }

    // Export CSV
    const exportCsvBtn = document.getElementById('btn-export-csv');
    if (exportCsvBtn) {
      exportCsvBtn.onclick = async () => {
        try {
          const blob = await api.get('/import-export/export-csv');
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `sentineledge_fleet_posture_${new Date().toISOString().slice(0, 10)}.csv`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          showToast('CSV export downloaded successfully.', 'success');
        } catch (err) {
          showToast(err.message, 'error');
        }
      };
    }

    // Export PDF
    const exportPdfBtn = document.getElementById('btn-export-pdf');
    if (exportPdfBtn) {
      exportPdfBtn.onclick = async () => {
        showToast('Generating Executive Posture PDF Report...', 'info');
        try {
          const blob = await api.get('/import-export/export-pdf');
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `sentineledge_executive_report_${new Date().toISOString().slice(0, 10)}.pdf`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          showToast('Executive PDF Report downloaded successfully.', 'success');
        } catch (err) {
          showToast(err.message, 'error');
        }
      };
    }
  },

  async uploadFile(file) {
    const summaryBox = document.getElementById('import-summary-box');
    summaryBox.innerHTML = `<div class="p-6 text-center text-slate-400 animate-pulse">Uploading and validating telemetry dataset with Pandas...</div>`;
    summaryBox.classList.remove('hidden');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await api.post('/import-export/import-csv', formData);
      summaryBox.innerHTML = `
        <div class="p-5 rounded-xl border ${
          res.errors.length > 0 ? 'bg-amber-950/20 border-amber-500/40' : 'bg-emerald-950/20 border-emerald-500/40'
        } space-y-3">
          <div class="flex items-center justify-between">
            <h4 class="font-bold text-white text-sm">Telemetry Ingestion Complete</h4>
            <span class="text-xs px-2 py-0.5 rounded font-mono font-bold ${
              res.errors.length > 0 ? 'bg-amber-900/40 text-amber-300' : 'bg-emerald-900/40 text-emerald-300'
            }">${res.errors.length > 0 ? 'Completed with Warnings' : 'Ingestion Success'}</span>
          </div>

          <div class="grid grid-cols-3 gap-3 text-xs text-center">
            <div class="p-2 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Total Processed</span>
              <span class="text-base font-bold text-slate-200 font-mono">${res.total_rows}</span>
            </div>
            <div class="p-2 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Created New</span>
              <span class="text-base font-bold text-emerald-400 font-mono">${res.created}</span>
            </div>
            <div class="p-2 rounded bg-slate-900/60 border border-slate-800">
              <span class="text-slate-400 block">Updated Existing</span>
              <span class="text-base font-bold text-cyan-400 font-mono">${res.updated}</span>
            </div>
          </div>

          ${res.errors.length > 0 ? `
            <div class="p-3 rounded bg-rose-950/40 border border-rose-900/60 text-xs text-rose-300 space-y-1">
              <div class="font-bold">Errors / Ingestion Issues:</div>
              ${res.errors.map(e => `<div>&bull; ${e}</div>`).join('')}
            </div>
          ` : ''}
        </div>
      `;
      showToast(`Imported ${res.total_rows} endpoint records successfully!`, 'success');
    } catch (err) {
      summaryBox.innerHTML = `
        <div class="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
          <strong>Import Failed:</strong> ${err.message}
        </div>
      `;
      showToast(err.message, 'error');
    }
  }
};

window.ImportExportPage = ImportExportPage;
