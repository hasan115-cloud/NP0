"use client";

import React, { useEffect, useRef, useState } from "react";
import { Header } from "./components/Header";
import { Sidebar } from "./components/Sidebar";
import { OverviewView } from "./components/OverviewView";
import { EnrolledSystemsView } from "./components/EnrolledSystemsView";
import { UrlHistoryView } from "./components/UrlHistoryView";
import { SecurityRulesView } from "./components/SecurityRulesView";
import { ThreatAlertsView } from "./components/ThreatAlertsView";
import { InstallExtensionView } from "./components/InstallExtensionView";
import { ReportsView } from "./components/ReportsView";
import { DashboardStats, EnrolledClient, NavigationTab } from "./types";
import { fetchClients, fetchServerInfo, fetchStats } from "./api";

const EMPTY_STATS: DashboardStats = {
  totalSystems: 0,
  urlsMonitored: 0,
  allowedUrls: 0,
  phishingIntercepted: 0,
  activeAlerts: 0,
  breakdown: {
    evaluated: 0,
    safe: 0,
    suspicious: 0,
    phishing: 0
  },
  recentEvents: [],
  topThreatDomains: []
};

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavigationTab>("overview");
  const [stats, setStats] = useState<DashboardStats>(EMPTY_STATS);
  const [clients, setClients] = useState<EnrolledClient[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [serverInfo, setServerInfo] = useState<{ database?: string; databaseHost?: string } | null>(null);

  // The selected system is owned HERE, not inside a single view, so that the
  // Overview counts and the URL History table always describe the same
  // scope. Previously Overview was hard-wired to fleet-wide totals while
  // History filtered per system, so the two disagreed whenever a specific
  // system was selected.
  const [selectedSystem, setSelectedSystem] = useState("ALL");

  // Request-sequencing guard for the 6-second poll. Without it, a slow
  // response from an earlier tick can land after a faster later one and
  // overwrite current numbers with stale ones — the counts would appear to
  // "change on their own." Only the newest in-flight request may write.
  const latestStatsRequest = useRef(0);

  const loadDashboardData = async (silent = false, scope = selectedSystem) => {
    const requestId = ++latestStatsRequest.current;
    if (!silent) setIsRefreshing(true);
    try {
      const [newStats, newClients] = await Promise.all([
        fetchStats(scope),
        fetchClients()
      ]);
      if (requestId !== latestStatsRequest.current) return;
      setStats(newStats);
      setClients(newClients);
    } catch (e) {
      console.error("Telemetry sync error:", e);
    } finally {
      if (!silent && requestId === latestStatsRequest.current) setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchServerInfo().then(setServerInfo).catch(() => {});
  }, []);

  useEffect(() => {
    loadDashboardData(false, selectedSystem);
    // Poll telemetry every 6 seconds to capture live heartbeats and navigation scans
    const timer = setInterval(() => {
      loadDashboardData(true, selectedSystem);
    }, 6000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedSystem]);

  return (
    <div className="min-h-screen bg-[#000000] text-neutral-100 flex flex-col font-sans">
      {/* SOC Top Header */}
      <Header
        totalCount={clients.length}
        onRefresh={() => loadDashboardData(false)}
        isRefreshing={isRefreshing}
        database={serverInfo?.database}
        databaseHost={serverInfo?.databaseHost}
      />

      {/* Main Body */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          activeAlertsCount={stats.activeAlerts}
          enrolledSystemsCount={clients.length}
        />

        {/* Dynamic Tab View Container */}
        <main className="flex-1 p-6 lg:p-8 overflow-y-auto bg-[#000000]">
          <div className="max-w-7xl mx-auto">
            {currentTab === "overview" && (
              <OverviewView
                stats={stats}
                clients={clients}
                selectedSystem={selectedSystem}
                onSelectSystem={setSelectedSystem}
                onNavigateTab={setCurrentTab}
              />
            )}

            {currentTab === "enrolled_systems" && (
              <EnrolledSystemsView
                clients={clients}
                onNavigateTab={setCurrentTab}
                onRefresh={() => loadDashboardData(false)}
              />
            )}

            {currentTab === "url_history" && (
              <UrlHistoryView
                clients={clients}
                selectedClient={selectedSystem}
                onSelectClient={setSelectedSystem}
              />
            )}

            {currentTab === "security_rules" && (
              <SecurityRulesView />
            )}

            {currentTab === "threat_alerts" && (
              <ThreatAlertsView
                clients={clients}
                onAlertUpdated={() => loadDashboardData(true)}
              />
            )}

            {currentTab === "install_extension" && (
              <InstallExtensionView />
            )}

            {currentTab === "reports" && (
              <ReportsView clients={clients} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
