// ---------- Global search (header) ----------
(function () {
  const input = document.getElementById("global-search-input");
  const resultsBox = document.getElementById("global-search-results");
  if (!input || !resultsBox) return;

  let timer = null;
  input.addEventListener("input", () => {
    clearTimeout(timer);
    const q = input.value.trim();
    if (q.length < 2) {
      resultsBox.classList.remove("open");
      resultsBox.innerHTML = "";
      return;
    }
    timer = setTimeout(() => {
      fetch(`/api/search?q=${encodeURIComponent(q)}`)
        .then((r) => r.json())
        .then((data) => renderResults(data.results))
        .catch(() => {});
    }, 250);
  });

  document.addEventListener("click", (e) => {
    if (!resultsBox.contains(e.target) && e.target !== input) {
      resultsBox.classList.remove("open");
    }
  });

  function renderResults(results) {
    if (!results || (!results.users.length && !results.organizations.length)) {
      resultsBox.innerHTML = '<div class="search-hit muted">No matches.</div>';
      resultsBox.classList.add("open");
      return;
    }
    let html = "";
    results.users.forEach((u) => {
      html += `<div class="search-hit"><strong>${escapeHtml(u.first_name)} ${escapeHtml(u.last_name)}</strong>
                <div class="muted">${escapeHtml(u.designation || "")} · ${escapeHtml(u.region || "")} · <span class="tag-mono">${escapeHtml(u.uisp_id)}</span></div></div>`;
    });
    results.organizations.forEach((o) => {
      html += `<div class="search-hit"><strong>${escapeHtml(o.org_name)}</strong>
                <div class="muted">Reg. No: ${escapeHtml(o.registration_number)}</div></div>`;
    });
    resultsBox.innerHTML = html;
    resultsBox.classList.add("open");
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (m) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[m]));
  }
})();

// ---------- Bento search (filters visible cards only) ----------
(function () {
  const input = document.getElementById("bento-search-input");
  if (!input) return;
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    document.querySelectorAll("[data-searchable]").forEach((el) => {
      const text = el.getAttribute("data-searchable").toLowerCase();
      el.style.display = text.includes(q) ? "" : "none";
    });
  });
})();

// ---------- Template selection (New Application) ----------
function selectTemplate(id, el) {
  document.querySelectorAll(".template-card").forEach((c) => c.classList.remove("selected"));
  el.classList.add("selected");
  document.getElementById("template_id_input").value = id;
}

// ---------- Rich-ish text editor toolbar ----------
function formatDoc(cmd) {
  document.execCommand(cmd, false, null);
}

function syncEditorContent() {
  const editor = document.getElementById("editor-body");
  const hidden = document.getElementById("content_body_input");
  if (editor && hidden) hidden.value = editor.innerHTML;
}

// ---------- Tabs (verification screen) ----------
function showTab(name) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  document.getElementById(`tab-btn-${name}`).classList.add("active");
  document.getElementById(`tab-panel-${name}`).classList.add("active");
}
