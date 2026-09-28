import React, { useEffect, useRef, useState } from "react";
import { Filter, Globe, Laptop, RefreshCw, Search, ShieldAlert } from "lucide-react";
import { EnrolledClient, UrlEvent } from "../types";
import { fetchEvents } from "../api";

interface UrlHistoryViewProps {
  clients: EnrolledClient[];
  // System scope is owned by App and shared with the Overview, so the two
  // views can never describe different record sets.
  selectedClient: string;
  onSelectClient: (clientId: string) => void;
}

export const UrlHistoryView: React.FC<UrlHistoryViewProps> = ({ clients, selectedClient, onSelectClient }) => {
  const [events, setEvents] = useState<UrlEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState("");
  const [selectedClassification, setSelectedClassification] = useState("ALL");

  // Request-sequencing guard: every call to loadData gets a new sequence
  // number, and only the response matching the LATEST outstanding request
  // is ever applied to state. Without this, a slower earlier request
  // (e.g. from a filter that was just changed) could resolve after a newer
  // one and silently overwrite fresh, complete data with stale/partial
  // data — this is exactly what caused history to "appear, then a moment
  // later revert or disappear." Whichever request was issued LAST always
  // wins, regardless of which one's network response arrives last.
  const latestRequestId = useRef(0);

  const loadData = async (silent = false) => {
    const requestId = ++latestRequestId.current;
    if (!silent) setIsLoading(true);
    setLoadError(null);
    try {
      // No limit is passed: the backend returns the COMPLETE matching
      // history in one response — the database is the single source of
      // truth, never a partial/cached frontend slice.
      const data = await fetchEvents({
        clientId: selectedClient,
        classification: selectedClassification,
        search
      });

      if (requestId !== latestRequestId.current) {
        // A newer request has since been issued (filter changed, refresh
        // clicked again, etc.) — this response is stale. Discard it so it
        // can never clobber more current data.
        return;
      }

      setEvents(data.events || []);
      setTotal(data.total || 0);
    } catch (e) {
      if (requestId !== latestRequestId.current) return;
      console.error("Failed to load events", e);
      setLoadError("Failed to load URL history from the server.");
    } finally {
      if (!silent && requestId === latestRequestId.current) {
        setIsLoading(false);
      }
    }
  };

  useEffect(() => {
    loadData();
    // Poll on the SAME 6s cadence the Overview uses. Previously this table
    // only reloaded on a filter change or a manual click, so a newly
    // recorded URL appeared in the Overview counts seconds before it
    // appeared here — which reads as the two views disagreeing. The
    // sequencing guard in loadData keeps a slow poll response from ever
    // overwriting fresher data.
    const timer = setInterval(() => loadData(true), 6000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedClient, selectedClassification]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadData();
  };

  const ruleTriggeredLabel = (evt: UrlEvent): string | null => {
    if (!evt.ruleTriggered) return null;
    if (evt.ruleType === "WHITELIST") return "Whitelist Rule Triggered";
    if (evt.ruleType === "PHISHING") return "Blacklist Rule Triggered";
    return "Rule Triggered";
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div className="min-w-0">
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2 flex-wrap">
            <span>URL Telemetry History</span>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30">
              {total} Records
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Complete navigation and link scan history across all connected PhishGuard endpoints — every record loads at once from the database.
          </p>
        </div>

        <button
          onClick={() => loadData()}
          disabled={isLoading}
          className="flex items-center gap-2 text-xs bg-[#161616] hover:bg-[#232323] text-neutral-300 hover:text-white px-3.5 py-2 rounded-lg border border-[#2a2a2a] transition-colors self-start sm:self-auto shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-[#ffffff]" : ""}`} />
          <span>Refresh Records</span>
        </button>
      </div>

      {/* Filter Controls Bar */}
      <div className="bg-[#0e0e0e] border border-[#262626] p-4 rounded-xl flex flex-wrap gap-3 items-center justify-between">
        <form onSubmit={handleSearchSubmit} className="flex-1 min-w-[240px] relative">
          <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-neutral-400" />
          <input
            type="text"
            placeholder="Search by domain, URL, or trigger reason..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-[#161616] border border-[#262626] text-neutral-200 text-xs pl-9 pr-3 py-2 rounded-lg focus:outline-none focus:border-[#ffffff]"
          />
        </form>

        <div className="flex flex-wrap items-center gap-3">
          {/* Client Filter */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Laptop className="w-3.5 h-3.5" />
            <select
              value={selectedClient}
              onChange={e => onSelectClient(e.target.value)}
              className="bg-[#161616] border border-[#262626] text-neutral-200 text-xs px-2.5 py-2 rounded-lg focus:outline-none"
            >
              <option value="ALL">All Connected Systems</option>
              {clients.map(c => (
                <option key={c.id} value={c.id}>
                  {c.clientName} ({c.id.slice(-6)})
                </option>
              ))}
            </select>
          </div>

          {/* Classification Filter */}
          <div className="flex items-center gap-2 text-xs text-neutral-400">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={selectedClassification}
              onChange={e => setSelectedClassification(e.target.value)}
              className="bg-[#161616] border border-[#262626] text-neutral-200 text-xs px-2.5 py-2 rounded-lg focus:outline-none"
            >
              <option value="ALL">All Classifications</option>
              <option value="SAFE">Safe</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="PHISHING">Phishing</option>
            </select>
          </div>
        </div>
      </div>

      {loadError && (
        <div className="bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs px-4 py-2.5 rounded-lg flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
          <span>{loadError}</span>
        </div>
      )}

      {/* URL History Table */}
      <div className="bg-[#0e0e0e] border border-[#262626] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-neutral-300">
            <thead className="bg-[#161616] text-neutral-400 font-semibold border-b border-[#262626]">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">System / Endpoint</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Domain & Destination</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Heuristics & Reason</th>
                <th className="py-3 px-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#262626]">
              {isLoading && events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-neutral-400">
                    <RefreshCw className="w-6 h-6 mx-auto animate-spin text-[#ffffff] mb-2" />
                    Loading complete URL history from database...
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-neutral-500">
                    <Globe className="w-10 h-10 mx-auto mb-2 opacity-50 text-neutral-600" />
                    <div className="text-sm font-medium text-neutral-400">No URL Events Matched</div>
                    <p className="text-xs text-neutral-500 max-w-sm mx-auto mt-1">
                      {search || selectedClient !== "ALL" || selectedClassification !== "ALL"
                        ? "Try clearing your filters to view more records."
                        : "No browsing events received yet. Once the extension is active on a system, evaluated URLs will appear here."}
                    </p>
                  </td>
                </tr>
              ) : (
                events.map(evt => {
                  const ruleLabel = ruleTriggeredLabel(evt);
                  return (
                    <tr key={evt.id} className="hover:bg-[#161616]/60 transition-colors">
                      <td className="py-3 px-4 text-neutral-400 font-mono text-[11px] whitespace-nowrap">
                        <div>{new Date(evt.timestamp).toLocaleDateString()}</div>
                        <div className="text-[10px] text-neutral-500">
                          {new Date(evt.timestamp).toLocaleTimeString()}
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <div className="font-semibold text-neutral-200">{evt.clientName}</div>
                        <div className="text-[10px] text-neutral-500 font-mono">{evt.source}</div>
                      </td>

                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            evt.classification === "PHISHING"
                              ? "bg-rose-500/15 text-rose-400 border border-rose-500/30"
                              : evt.classification === "SUSPICIOUS"
                              ? "bg-amber-500/15 text-amber-400 border border-amber-500/30"
                              : "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
                          }`}
                        >
                          {evt.classification === "PHISHING" ? "🛑" : evt.classification === "SUSPICIOUS" ? "⚠️" : "✅"}
                          {evt.classification}
                        </span>
                      </td>

                      <td className="py-3 px-4 max-w-xs">
                        <div className="font-mono text-neutral-200 truncate font-semibold">{evt.domain}</div>
                        <div className="text-[10px] text-neutral-500 truncate" title={evt.url}>{evt.url}</div>
                        {ruleLabel && (
                          <span className="inline-flex items-center gap-1 mt-1 text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded bg-white/10 text-white border border-white/30">
                            <ShieldAlert className="w-2.5 h-2.5" />
                            {ruleLabel}
                          </span>
                        )}
                      </td>

                      <td className="py-3 px-4 font-mono">
                        <span className={`text-xs font-bold ${evt.score >= 0.65 ? "text-rose-400" : evt.score >= 0.4 ? "text-amber-400" : "text-emerald-400"}`}>
                          {(evt.score * 100).toFixed(0)}%
                        </span>
                      </td>

                      <td className="py-3 px-4 text-neutral-300 text-[11px] max-w-sm truncate" title={evt.reason}>
                        {evt.reason || "Standard heuristic"}
                      </td>

                      <td className="py-3 px-4 font-semibold text-[11px]">
                        <span className={evt.verdict === "BLOCKED" ? "text-rose-400" : evt.verdict === "WARNING" ? "text-amber-400" : "text-emerald-400"}>
                          {evt.verdict}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between px-4 py-3 border-t border-[#262626] text-xs text-neutral-400">
          <span>
            Showing all {events.length} of {total} matching records — complete history, loaded from the database in one request.
          </span>
        </div>
      </div>
    </div>
  );
};
