"use strict";
const $ = id => document.getElementById(id);
const selected = new Map();
const launchToken = location.hash.slice(1);
let accessToken = "";
try { accessToken = sessionStorage.getItem("collectorAccessToken") || ""; } catch {}
if (/^[A-Za-z0-9_-]{43}$/.test(launchToken)) {
  accessToken = launchToken;
  try { sessionStorage.setItem("collectorAccessToken", launchToken); } catch {}
  history.replaceState(null, "", location.pathname + location.search);
}
let session = null, results = [], page = 1, lastQuery = "", currentJob = null, pollTimer = null, searchController = null, closed = false;
function notice(message) { $("notice").textContent = message; $("notice").hidden = !message; }
async function api(path, options = {}) {
  const headers = { ...options.headers, Authorization: "Bearer " + accessToken };
  if (options.method && options.method !== "GET") { headers["X-CSRF-Token"] = session?.csrfToken || ""; headers["Content-Type"] = "application/json"; }
  const response = await fetch("/api/" + path, { ...options, headers, credentials: "same-origin", cache: "no-store" });
  let data;
  try { data = await response.json(); } catch { throw new Error("Programla bağlantı kesildi. Programı yeniden açabilirsiniz."); }
  if (!response.ok) throw new Error(data.error || "İşlem tamamlanamadı. Tekrar deneyin.");
  return data;
}
function busy() { return currentJob?.status === "running"; }
function updateButtons() {
  $("selected-count").textContent = selected.size;
  $("clear-selection").disabled = !selected.size || busy();
  $("download").disabled = !session || !selected.size || !$("destination").value.trim() || busy() || closed;
  $("choose-folder").disabled = !session || busy() || closed;
  $("destination").disabled = busy() || closed;
  $("close-app").disabled = busy() || closed;
  $("cancel").hidden = !busy();
}
function renderSelection() {
  $("selected-list").replaceChildren();
  for (const [id, entry] of selected) {
    const row = document.createElement("div"); row.className = "selected-row";
    const text = document.createElement("span"); text.textContent = entry.name || id;
    const identity = document.createElement("small"); identity.textContent = id; text.append(identity);
    const remove = document.createElement("button"); remove.type = "button"; remove.setAttribute("aria-label", (entry.name || id) + " (" + id + ") seçimini kaldır"); remove.disabled = busy();
    remove.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-x"/></svg>';
    remove.addEventListener("click", () => { selected.delete(id); renderSelection(); renderResults(); });
    row.append(text, remove); $("selected-list").append(row);
  }
  $("selection-empty").hidden = selected.size > 0; updateButtons();
}
function renderResults() {
  $("results").replaceChildren();
  for (const entry of results) {
    const fragment = $("result-template").content.cloneNode(true), row = fragment.querySelector("article"), checkbox = fragment.querySelector("input");
    fragment.querySelector(".result-name").textContent = entry.name;
    fragment.querySelector(".result-id").textContent = entry.id;
    fragment.querySelector(".result-description").textContent = entry.description;
    fragment.querySelector(".publisher-name").textContent = entry.publisher || entry.id.split(".")[0];
    const badge = fragment.querySelector(".verified"); badge.hidden = !entry.verified; badge.title = "Marketplace bu yayıncının alan adını doğrulamış. Bu, zararlı yazılım taraması anlamına gelmez.";
    const link = fragment.querySelector("a"); link.href = "https://marketplace.visualstudio.com/items?itemName=" + encodeURIComponent(entry.id); link.setAttribute("aria-label", entry.name + " (" + entry.id + ") resmi mağaza sayfasını aç");
    checkbox.checked = selected.has(entry.id); checkbox.disabled = busy() || closed; checkbox.setAttribute("aria-label", entry.name + " (" + entry.id + ") seç"); row.classList.toggle("is-selected", checkbox.checked);
    checkbox.addEventListener("change", () => { if (checkbox.checked) selected.set(entry.id, entry); else selected.delete(entry.id); row.classList.toggle("is-selected", checkbox.checked); renderSelection(); });
    $("results").append(fragment);
  }
}
async function search(targetPage = 1) {
  const query = $("query").value.trim();
  if (query.length < 2) { $("query").focus(); return; }
  searchController?.abort(); searchController = new AbortController(); const controller = searchController;
  $("search-button").disabled = true; $("search-button").textContent = "Aranıyor…"; $("results").setAttribute("aria-busy", "true"); notice("");
  try {
    const data = await api("search?q=" + encodeURIComponent(query) + "&page=" + targetPage, { signal: controller.signal });
    results = data.entries; page = data.page; lastQuery = query; renderResults();
    $("result-summary").textContent = results.length ? results.length + " sonuç · “" + query + "”" : "Sonuç bulunamadı";
    $("search-empty").hidden = results.length > 0;
    if (!results.length) {
      $("search-empty").querySelector("h2").textContent = "Bu arama için eklenti bulunamadı.";
      $("search-empty").querySelector("p").textContent = "Eklenti adını veya yayıncı.eklenti kimliğini kontrol edip tekrar arayın.";
    }
    $("pagination").hidden = !results.length && page === 1; $("previous").disabled = page === 1; $("next").disabled = !data.hasMore; $("page-label").textContent = "Sayfa " + page;
    $("connection").textContent = "Hazır · Marketplace bağlantısı kuruldu";
  } catch (error) { if (error.name !== "AbortError") { notice(error.message); $("connection").textContent = "Marketplace bağlantısı kurulamadı"; } }
  finally { if (controller === searchController) { $("search-button").disabled = closed; $("search-button").textContent = "Ara"; $("results").setAttribute("aria-busy", "false"); } }
}
function renderJob(job) {
  currentJob = job; $("download-empty").hidden = true; $("job-state").hidden = false; $("open-folder").hidden = busy();
  const failed = job.results.filter(r => r.status === "failed" || r.status === "renamed");
  const labels = { running: "Paketler hazırlanıyor", completed: "Aktarım paketi hazır", partial: "İndirme eksiklerle tamamlandı", canceled: "İndirme durduruldu", failed: "İndirme tamamlanamadı" };
  $("job-title").textContent = (labels[job.status] || job.status) + " · " + job.completed + " paket indirildi";
  $("job-title").className = "job-title" + (job.status === "completed" ? " success" : "");
  $("job-current").textContent = job.error || (busy() ? (job.current ? "Hazırlanıyor: " + job.current : job.results.length ? "Aktarım raporu hazırlanıyor…" : "İndirme başlatılıyor…") : failed.length ? failed.length + " paket için ayrıntıları kontrol edin. Hazır dosyalar klasörde korundu." : job.status === "canceled" ? "Tamamlanan paketler klasörde korundu." : "Gerekli bağımlılıklar, imza dosyaları ve aktarım raporu klasöre eklendi.");
  $("job-folder").textContent = job.folder; $("job-count").textContent = "(" + job.results.length + ")"; $("job-results").replaceChildren();
  for (const result of job.results) {
    const row = document.createElement("div"); row.className = "job-result";
    const identity = document.createElement("div"); identity.textContent = result.id + (result.version ? " · " + result.version : "");
    const detail = document.createElement("small"); detail.textContent = result.error || (result.reason === "requested" ? "Seçilen eklenti" : "Otomatik eklendi"); identity.append(detail);
    const status = document.createElement("span"); status.className = result.status === "collected" ? "ok" : "error"; status.textContent = result.status === "collected" ? "İndirildi" : result.status === "renamed" ? "Kimlik değişmiş" : "İndirilemedi";
    row.append(identity, status); $("job-results").append(row);
  }
  $("retry").hidden = busy() || !(job.status === "canceled" || job.status === "failed" || job.results.some(r => r.status === "failed"));
  if (failed.length && !busy()) $("job-details").open = true;
  renderSelection(); renderResults();
}
function schedulePoll() {
  clearTimeout(pollTimer);
  if (!busy() || closed) return;
  pollTimer = setTimeout(async () => { try { renderJob(await api("jobs/" + currentJob.id)); schedulePoll(); } catch (error) { notice(error.message); if (!closed) pollTimer = setTimeout(schedulePoll, 2000); } }, 1000);
}
async function download(ids) {
  $("download").disabled = true; notice("");
  try { const job = await api("jobs", { method: "POST", body: JSON.stringify({ ids, destination: $("destination").value.trim() }) }); renderJob(job); $("download-heading").scrollIntoView({block:"start",behavior:"instant"}); schedulePoll(); }
  catch (error) { notice(error.message); updateButtons(); }
}
$("search-form").addEventListener("submit", event => { event.preventDefault(); search(); });
document.querySelectorAll("[data-search]").forEach(button => button.addEventListener("click", () => { $("query").value = button.dataset.search; search(); }));
$("previous").addEventListener("click", () => { $("query").value = lastQuery; search(page - 1); });
$("next").addEventListener("click", () => { $("query").value = lastQuery; search(page + 1); });
$("clear-selection").addEventListener("click", () => { selected.clear(); renderSelection(); renderResults(); });
$("destination").addEventListener("input", updateButtons);
$("choose-folder").addEventListener("click", async () => { const button = $("choose-folder"); button.disabled = true; notice(""); try { const data = await api("folder", { method: "POST" }); if (!data.canceled) $("destination").value = data.path; } catch (error) { notice(error.message); } finally { updateButtons(); } });
$("download").addEventListener("click", () => download([...selected.keys()]));
$("cancel").addEventListener("click", async () => { $("cancel").disabled = true; try { await api("jobs/" + currentJob.id + "/cancel", { method: "POST" }); } catch (error) { notice(error.message); } finally { $("cancel").disabled = false; } });
$("open-folder").addEventListener("click", async () => { try { await api("jobs/" + currentJob.id + "/open", { method: "POST" }); } catch (error) { notice(error.message); } });
$("retry").addEventListener("click", () => download(currentJob.requested));
$("close-app").addEventListener("click", async () => { try { await api("close", { method: "POST" }); closed = true; clearTimeout(pollTimer); searchController?.abort(); $("connection").textContent = "Program kapatıldı · Bu sekmeyi kapatabilirsiniz"; notice("Program kapatıldı. Yeniden kullanmak için EXE dosyasını açın."); updateButtons(); $("search-button").disabled = true; renderResults(); } catch (error) { notice(error.message); } });
(async () => { try { session = await api("session"); $("destination").value = session.destination; $("connection").textContent = "Hazır · Bu bilgisayarda çalışıyor"; updateButtons(); const history = await api("jobs"); if (history.jobs.length) { renderJob(history.jobs[0]); schedulePoll(); } } catch (error) { notice(error.message); $("connection").textContent = "Yerel oturum açılamadı"; } })();
