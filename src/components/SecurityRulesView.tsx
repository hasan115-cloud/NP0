import React, { useEffect, useState } from "react";
import { AlertOctagon, CheckCircle2, Plus, ShieldCheck, Trash2, Zap } from "lucide-react";
import { PhishingRule, WhitelistRule } from "../types";
import {
  addPhishingRule,
  addWhitelistRule,
  deletePhishingRule,
  deleteWhitelistRule,
  fetchRules
} from "../api";

export const SecurityRulesView: React.FC = () => {
  const [whitelist, setWhitelist] = useState<WhitelistRule[]>([]);
  const [phishingRules, setPhishingRules] = useState<PhishingRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // New Whitelist Rule State
  const [whitePattern, setWhitePattern] = useState("");
  const [whiteDesc, setWhiteDesc] = useState("");
  const [isAddingWhite, setIsAddingWhite] = useState(false);

  // New Phishing Rule State
  const [phishPattern, setPhishPattern] = useState("");
  const [phishSeverity, setPhishSeverity] = useState<"HIGH" | "CRITICAL">("HIGH");
  const [phishReason, setPhishReason] = useState("");
  const [isAddingPhish, setIsAddingPhish] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ text: string; isError?: boolean } | null>(null);

  const showStatus = (text: string, isError = false) => {
    setStatusMsg({ text, isError });
    setTimeout(() => setStatusMsg(null), 3500);
  };

  const loadRules = async () => {
    setIsLoading(true);
    try {
      const data = await fetchRules();
      setWhitelist(data.whitelist || []);
      setPhishingRules(data.phishing || []);
    } catch (e) {
      console.error("Failed to load rules", e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, []);

  const handleAddWhitelist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!whitePattern.trim()) return;
    setIsAddingWhite(true);
    try {
      await addWhitelistRule(whitePattern.trim(), whiteDesc.trim());
      setWhitePattern("");
      setWhiteDesc("");
      showStatus("Whitelist rule added successfully");
      loadRules();
    } catch (e) {
      showStatus("Failed to add whitelist rule", true);
    } finally {
      setIsAddingWhite(false);
    }
  };

  const handleDeleteWhitelist = async (id: string) => {
    try {
      await deleteWhitelistRule(id);
      showStatus("Whitelist rule removed");
      loadRules();
    } catch (e) {
      showStatus("Failed to delete whitelist rule", true);
    }
  };

  const handleAddPhishing = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!phishPattern.trim()) return;
    setIsAddingPhish(true);
    try {
      await addPhishingRule(phishPattern.trim(), phishSeverity, phishReason.trim());
      setPhishPattern("");
      setPhishReason("");
      showStatus("Phishing interception policy added");
      loadRules();
    } catch (e) {
      showStatus("Failed to add phishing rule", true);
    } finally {
      setIsAddingPhish(false);
    }
  };

  const handleDeletePhishing = async (id: string) => {
    try {
      await deletePhishingRule(id);
      showStatus("Phishing policy rule removed");
      loadRules();
    } catch (e) {
      showStatus("Failed to delete phishing rule", true);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl">
        <div>
          <h2 className="text-xl font-bold text-neutral-100 flex items-center gap-2">
            <span>Security Rules & Policy</span>
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-[#1f1f1f] text-[#ffffff] border border-[#ffffff]/30">
              {whitelist.length + phishingRules.length} Active Rules
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-1">
            Global network detection policies enforced directly across all connected browser extensions during evaluation and heartbeat sync.
          </p>
        </div>

        {/* Sync status indicator */}
        <div className="flex items-center gap-2 bg-[#161616] border border-[#2a2a2a] px-3.5 py-2 rounded-lg text-xs">
          <Zap className="w-3.5 h-3.5 text-amber-400" />
          <span className="text-neutral-300">Heartbeat Sync: <strong className="text-emerald-400">Real-Time</strong></span>
        </div>
      </div>

      {statusMsg && (
        <div
          className={`px-4 py-2.5 rounded-lg text-xs font-medium flex items-center justify-between transition-all ${
            statusMsg.isError
              ? "bg-rose-500/15 border border-rose-500/30 text-rose-300"
              : "bg-emerald-500/15 border border-emerald-500/30 text-emerald-300"
          }`}
        >
          <span>{statusMsg.text}</span>
          <button onClick={() => setStatusMsg(null)} className="opacity-70 hover:opacity-100 text-xs">✕</button>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Area A: Whitelist Rules */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-neutral-100">Whitelist Rules (Always Allowed)</h3>
              </div>
              <span className="text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded font-bold">
                {whitelist.length} Rules
              </span>
            </div>
            <p className="text-xs text-neutral-400 mb-4">
              Domains or URL patterns in this list bypass phishing heuristics and are guaranteed safe across all client endpoints.
            </p>

            {/* Add Rule Form */}
            <form onSubmit={handleAddWhitelist} className="bg-[#161616] border border-[#262626] p-3 rounded-lg mb-4 space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <input
                  type="text"
                  placeholder="e.g. internal.corp.com or mydomain.org"
                  value={whitePattern}
                  onChange={e => setWhitePattern(e.target.value)}
                  className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-emerald-400 font-mono"
                  required
                />
                <input
                  type="text"
                  placeholder="Description / Reason"
                  value={whiteDesc}
                  onChange={e => setWhiteDesc(e.target.value)}
                  className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-emerald-400"
                />
              </div>
              <button
                type="submit"
                disabled={isAddingWhite}
                className="w-full flex items-center justify-center gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold py-1.5 rounded transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Whitelist Rule</span>
              </button>
            </form>

            {/* Whitelist Table */}
            <div className="max-h-72 overflow-y-auto space-y-1.5">
              {whitelist.length === 0 ? (
                <div className="py-6 text-center text-neutral-500 text-xs">
                  No whitelist rules configured. Add internal corporate domains to exempt them from scans.
                </div>
              ) : (
                whitelist.map(rule => (
                  <div
                    key={rule.id}
                    className="flex items-center justify-between p-2.5 bg-[#161616] border border-[#262626] rounded-lg text-xs"
                  >
                    <div className="overflow-hidden mr-2">
                      <div className="font-mono font-bold text-neutral-100 truncate">{rule.pattern}</div>
                      <div className="text-[10px] text-neutral-400 truncate">{rule.description}</div>
                    </div>
                    <button
                      onClick={() => handleDeleteWhitelist(rule.id)}
                      className="text-neutral-500 hover:text-rose-400 p-1 transition-colors"
                      title="Delete Rule"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Area B: Phishing Rules */}
        <div className="bg-[#0e0e0e] border border-[#262626] p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <AlertOctagon className="w-5 h-5 text-rose-500" />
                <h3 className="text-sm font-bold text-neutral-100">Phishing Rules (Mandatory Block)</h3>
              </div>
              <span className="text-xs font-mono bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded font-bold">
                {phishingRules.length} Rules
              </span>
            </div>
            <p className="text-xs text-neutral-400 mb-4">
              Domains or patterns matching these rules are immediately intercepted, blocked with a warning screen, and alerted.
            </p>

            {/* Add Phishing Form */}
            <form onSubmit={handleAddPhishing} className="bg-[#161616] border border-[#262626] p-3 rounded-lg mb-4 space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <input
                  type="text"
                  placeholder="e.g. evil-login-phish.xyz"
                  value={phishPattern}
                  onChange={e => setPhishPattern(e.target.value)}
                  className="sm:col-span-2 bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-rose-400 font-mono"
                  required
                />
                <select
                  value={phishSeverity}
                  onChange={e => setPhishSeverity(e.target.value as any)}
                  className="bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-2 py-2 rounded focus:outline-none"
                >
                  <option value="HIGH">High Risk</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
              <input
                type="text"
                placeholder="Threat Reason (e.g. Credential Harvester Campaign)"
                value={phishReason}
                onChange={e => setPhishReason(e.target.value)}
                className="w-full bg-[#000000] border border-[#262626] text-neutral-200 text-xs px-3 py-2 rounded focus:outline-none focus:border-rose-400"
              />
              <button
                type="submit"
                disabled={isAddingPhish}
                className="w-full flex items-center justify-center gap-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold py-1.5 rounded transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Phishing Rule</span>
              </button>
            </form>

            {/* Phishing Rules Table */}
            <div className="max-h-72 overflow-y-auto space-y-1.5">
              {phishingRules.length === 0 ? (
                <div className="py-6 text-center text-neutral-500 text-xs">
                  No custom phishing rules configured. You can define specific domains or malicious patterns to block immediately.
                </div>
              ) : (
                phishingRules.map(rule => (
                  <div
                    key={rule.id}
                    className="flex items-center justify-between p-2.5 bg-[#161616] border border-rose-500/20 rounded-lg text-xs"
                  >
                    <div className="overflow-hidden mr-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-rose-400 truncate">{rule.pattern}</span>
                        <span className="text-[9px] font-bold uppercase px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300">
                          {rule.severity}
                        </span>
                      </div>
                      <div className="text-[10px] text-neutral-400 truncate">{rule.reason}</div>
                    </div>
                    <button
                      onClick={() => handleDeletePhishing(rule.id)}
                      className="text-neutral-500 hover:text-rose-400 p-1 transition-colors"
                      title="Delete Rule"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
