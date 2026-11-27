import {
  act,
  render,
  screen,
  fireEvent,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { resetMockIpcState } from "../lib/ipc";
import type {
  ActionResult,
  DesktopStatusSnapshot,
  UpdateCheckPayload,
} from "../types";

type StatusSnapshotOverride =
  | Partial<DesktopStatusSnapshot>
  | ((snapshot: DesktopStatusSnapshot) => DesktopStatusSnapshot);

let statusSnapshotOverride: StatusSnapshotOverride | null = null;
let checkUpdatesOverride:
  | ((force?: boolean) => Promise<UpdateCheckPayload>)
  | null = null;
let upgradeServiceOverride: (() => Promise<ActionResult>) | null = null;

vi.mock("../lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/ipc")>();
  const applyOverride = (
    snapshot: DesktopStatusSnapshot,
  ): DesktopStatusSnapshot => {
    if (!statusSnapshotOverride) {
      return snapshot;
    }
    return typeof statusSnapshotOverride === "function"
      ? statusSnapshotOverride(snapshot)
      : { ...snapshot, ...statusSnapshotOverride };
  };
  return {
    ...actual,
    getStatus: async (force?: boolean) =>
      applyOverride(await actual.getStatus(force)),
    subscribeStatus: async (cb: (snapshot: DesktopStatusSnapshot) => void) =>
      actual.subscribeStatus((snapshot) => cb(applyOverride(snapshot))),
    checkUpdates: async (force?: boolean) =>
      checkUpdatesOverride
        ? checkUpdatesOverride(force)
        : actual.checkUpdates(force),
    upgradeService: async () =>
      upgradeServiceOverride
        ? upgradeServiceOverride()
        : actual.upgradeService(),
  };
});

function getNavButton(name: RegExp | string) {
  const nav = screen.getByRole("navigation", { name: "Primary" });
  return within(nav).getByRole("button", { name });
}

describe("App", () => {
  beforeEach(() => {
    window.localStorage.clear();
    document.body.style.overflow = "";
    statusSnapshotOverride = null;
    checkUpdatesOverride = null;
    upgradeServiceOverride = null;
    resetMockIpcState();
    vi.clearAllMocks();
  });

  afterEach(() => {
    window.localStorage.clear();
    document.body.style.overflow = "";
    statusSnapshotOverride = null;
    checkUpdatesOverride = null;
    upgradeServiceOverride = null;
    resetMockIpcState();
  });

  it("renders the Overview dashboard with live protection status and telemetry", async () => {
    render(<App />);

    expect(
      await screen.findByRole("heading", { name: "Protected" }),
    ).toBeInTheDocument();

    expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled();

    const engineGroup = screen.getByRole("radiogroup");
    expect(
      within(engineGroup).getByRole("radio", { name: "TUN" }),
    ).toHaveAttribute("aria-checked", "true");
    expect(
      within(engineGroup).getByRole("radio", { name: "Proxy" }),
    ).toHaveAttribute("aria-checked", "false");

    const telemetry = screen.getByLabelText("Live telemetry");
    expect(within(telemetry).getByText("Session Transfer")).toBeInTheDocument();
    expect(within(telemetry).getByText("1.1.1.1")).toBeInTheDocument();
    expect(within(telemetry).getByText("DoH")).toBeInTheDocument();
    expect(
      within(telemetry).getByRole("button", { name: /Split: 2 excluded/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Throughput" }),
    ).toBeInTheDocument();

    expect(screen.getByText("TUN · Active")).toBeInTheDocument();
    expect(screen.getByText("Window only")).toBeInTheDocument();
  });

  it("switches across all 6 navigation tabs cleanly", async () => {
    render(<App />);

    await screen.findByRole("heading", { name: "Protected" });
    expect(getNavButton("Overview")).toHaveAttribute("aria-current", "page");

    // 2. Split Tunnel
    fireEvent.click(getNavButton(/Split Tunnel/i));
    expect(
      await screen.findByRole("heading", { name: "Split Tunneling" }),
    ).toBeInTheDocument();
    expect(getNavButton(/Split Tunnel/i)).toHaveAttribute(
      "aria-current",
      "page",
    );

    // 3. DNS & Rules
    fireEvent.click(getNavButton("DNS & Rules"));
    expect(
      await screen.findByRole("heading", { name: "DNS & Rules" }),
    ).toBeInTheDocument();
    expect(getNavButton("DNS & Rules")).toHaveAttribute("aria-current", "page");

    // 4. Diagnostics
    fireEvent.click(getNavButton("Diagnostics"));
    expect(
      await screen.findByRole("heading", { name: "Diagnostics" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Ready to run diagnostics")).toBeInTheDocument();
    expect(getNavButton("Diagnostics")).toHaveAttribute("aria-current", "page");

    // 5. Settings
    fireEvent.click(getNavButton("Settings"));
    expect(
      await screen.findByRole("heading", { name: "Window & System Tray" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Background Service" }),
    ).toBeInTheDocument();
    expect(getNavButton("Settings")).toHaveAttribute("aria-current", "page");

    // 6. Installation
    fireEvent.click(getNavButton("Installation"));
    expect(
      await screen.findByRole("heading", { name: "Installation" }),
    ).toBeInTheDocument();
    expect(getNavButton("Installation")).toHaveAttribute(
      "aria-current",
      "page",
    );

    // Back to Overview
    fireEvent.click(getNavButton("Overview"));
    expect(
      await screen.findByRole("heading", { name: "Protected" }),
    ).toBeInTheDocument();
  });

  it("toggles Connect/Pause protection state and switches between TUN and Proxy engines", async () => {
    render(<App />);

    await screen.findByRole("heading", { name: "Protected" });

    // Pause protection
    fireEvent.click(screen.getByRole("button", { name: "Pause" }));
    expect(
      await screen.findByRole("heading", { name: "Paused" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Connect" })).toBeEnabled();

    // Reconnect protection
    fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(
      await screen.findByRole("heading", { name: "Protected" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled();

    // Switch engine from TUN to Proxy while running -> prompts confirmation dialog
    fireEvent.click(screen.getByRole("radio", { name: "Proxy" }));
    const cancelDialog = await screen.findByRole("dialog", {
      name: "Switch engine to Proxy?",
    });
    // Cancelling leaves TUN active
    fireEvent.click(within(cancelDialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(screen.getByRole("radio", { name: "TUN" })).toHaveAttribute(
      "aria-checked",
      "true",
    );

    // Confirm switching engine from TUN to Proxy
    fireEvent.click(screen.getByRole("radio", { name: "Proxy" }));
    const proxyDialog = await screen.findByRole("dialog", {
      name: "Switch engine to Proxy?",
    });
    fireEvent.click(
      within(proxyDialog).getByRole("button", { name: "Switch to Proxy" }),
    );

    await waitFor(() => {
      expect(screen.getByRole("radio", { name: "Proxy" })).toHaveAttribute(
        "aria-checked",
        "true",
      );
    });
    expect(screen.getByRole("radio", { name: "TUN" })).toHaveAttribute(
      "aria-checked",
      "false",
    );
    expect(screen.getByText(/127\.0\.0\.1:18080/)).toBeInTheDocument();
    expect(screen.getByText("Proxy · :18080")).toBeInTheDocument();

    // Switch back from Proxy to TUN while running -> confirm dialog
    fireEvent.click(screen.getByRole("radio", { name: "TUN" }));
    const tunDialog = await screen.findByRole("dialog", {
      name: "Switch engine to TUN?",
    });
    fireEvent.click(
      within(tunDialog).getByRole("button", { name: "Switch to TUN" }),
    );
    await waitFor(() => {
      expect(screen.getByRole("radio", { name: "TUN" })).toHaveAttribute(
        "aria-checked",
        "true",
      );
    });
    expect(screen.getByText(/vdpi-tun0 via Ethernet/)).toBeInTheDocument();
  });

  it("redacts custom DoH URL profile tokens across DNS & Rules and Overview UI", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    fireEvent.click(getNavButton("DNS & Rules"));
    await screen.findByRole("heading", { name: "DNS & Rules" });

    // Select Custom DNS card
    fireEvent.click(
      screen.getByRole("radio", { name: /Custom DNS/i }),
    );

    const customInput = screen.getByLabelText(
      "Custom IP Address or DoH Endpoint URL",
    );
    expect(customInput).toHaveAttribute("type", "text");

    const secretToken = "secret-profile-999";
    const secretDohUrl = `https://dns.nextdns.io/${secretToken}/dns-query`;
    fireEvent.change(customInput, { target: { value: secretDohUrl } });
    expect(customInput).toHaveAttribute("type", "password");

    const preview = screen.getByLabelText("Redacted DNS preview");
    expect(preview).toHaveTextContent("https://dns.nextdns.io/[hidden]");
    expect(preview).not.toHaveTextContent(secretToken);

    // Encrypted DNS (DoH) switch should be locked ON for custom https:// URL
    const dohSwitch = screen.getByRole("switch", {
      name: /Encrypted DNS \(DoH\)/i,
    });
    expect(dohSwitch).toHaveAttribute("aria-checked", "true");
    expect(dohSwitch).toBeDisabled();

    // Save & Apply custom DoH URL
    const stickyBar = screen.getByRole("region", {
      name: "Unsaved DNS and rule changes",
    });
    fireEvent.click(within(stickyBar).getByRole("button", { name: "Save & Apply" }));

    await waitFor(() => {
      expect(
        screen.queryByRole("region", { name: "Unsaved DNS and rule changes" }),
      ).not.toBeInTheDocument();
    });

    // Switch back to Overview and confirm redacted DoH preview is displayed without leaking token
    fireEvent.click(getNavButton("Overview"));
    await screen.findByRole("heading", { name: "Protected" });

    const telemetry = screen.getByLabelText("Live telemetry");
    expect(
      within(telemetry).getByText("https://dns.nextdns.io/[hidden]"),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(secretToken);
  });

  it("defaults Keep in system tray when closed to OFF and persists tray toggles", async () => {
    const firstRender = render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    // Sidebar initially reflects tray OFF
    expect(screen.getByText("Window only")).toBeInTheDocument();

    fireEvent.click(getNavButton("Settings"));
    await screen.findByRole("heading", { name: "Window & System Tray" });

    const keepInTraySwitch = screen.getByRole("switch", {
      name: "Keep in system tray when closed",
    });
    const minimizeToTraySwitch = screen.getByRole("switch", {
      name: "Minimize to system tray",
    });
    const startMinimizedSwitch = screen.getByRole("switch", {
      name: "Start minimized to tray",
    });

    expect(keepInTraySwitch).toHaveAttribute("aria-checked", "false");
    expect(minimizeToTraySwitch).toHaveAttribute("aria-checked", "false");
    expect(startMinimizedSwitch).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText("No tray icon")).toBeInTheDocument();
    expect(
      screen.queryByRole("switch", { name: "Show taskbar icon when minimized" }),
    ).not.toBeInTheDocument();

    // Toggle "Keep in system tray when closed" ON
    fireEvent.click(keepInTraySwitch);
    await waitFor(() => {
      expect(keepInTraySwitch).toHaveAttribute("aria-checked", "true");
    });
    expect(screen.getByText("Tray active")).toBeInTheDocument();
    expect(screen.getByText("Tray on")).toBeInTheDocument();

    // Toggle "Minimize to system tray" ON and verify nested taskbar icon toggle appears
    // below "Start minimized to tray" and defaults to OFF (showTaskbarIconWhenMinimized: false)
    fireEvent.click(minimizeToTraySwitch);
    await waitFor(() => {
      expect(minimizeToTraySwitch).toHaveAttribute("aria-checked", "true");
    });
    const showTaskbarSwitch = await screen.findByRole("switch", {
      name: "Show taskbar icon when minimized",
    });
    expect(showTaskbarSwitch).toHaveAttribute("aria-checked", "false");
    expect(
      Boolean(
        startMinimizedSwitch.compareDocumentPosition(showTaskbarSwitch) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ),
    ).toBe(true);

    fireEvent.click(showTaskbarSwitch);
    await waitFor(() => {
      expect(showTaskbarSwitch).toHaveAttribute("aria-checked", "true");
    });

    // Unmount and remount App without resetting IPC store to verify persistence
    firstRender.unmount();
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });
    expect(screen.getByText("Tray on")).toBeInTheDocument();

    fireEvent.click(getNavButton("Settings"));
    await screen.findByRole("heading", { name: "Window & System Tray" });
    expect(
      screen.getByRole("switch", { name: "Keep in system tray when closed" }),
    ).toHaveAttribute("aria-checked", "true");
    expect(
      screen.getByRole("switch", { name: "Minimize to system tray" }),
    ).toHaveAttribute("aria-checked", "true");
    expect(
      screen.getByRole("switch", { name: "Show taskbar icon when minimized" }),
    ).toHaveAttribute("aria-checked", "true");
  });

  it("runs read-only Diagnostics and copies the redacted report", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    fireEvent.click(getNavButton("Diagnostics"));
    await screen.findByRole("heading", { name: "Diagnostics" });

    const copyBtn = screen.getByRole("button", {
      name: "Copy Redacted Report",
    });
    expect(copyBtn).toBeDisabled();

    fireEvent.click(screen.getByRole("button", { name: "Run Diagnostics" }));

    expect(
      await screen.findByText(/All checks passed \(6\/6\)/i),
    ).toBeInTheDocument();

    const resultsCard = screen.getByLabelText("Diagnostic check results");
    expect(within(resultsCard).getByText("VPN coexistence")).toBeInTheDocument();
    expect(within(resultsCard).getByText("Wintun driver")).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Encrypted DNS (DoH)"),
    ).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Discord Web & Gateway"),
    ).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Roblox ClientSettings"),
    ).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Service & Runtime Hygiene"),
    ).toBeInTheDocument();

    expect(copyBtn).toBeEnabled();
    fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(navigator.clipboard.writeText).toHaveBeenCalledTimes(1);
    });
    expect(
      vi.mocked(navigator.clipboard.writeText).mock.calls[0][0],
    ).toContain("vdpi Diagnostics Report");
    expect(await screen.findByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("guards dirty tab switches with ConfirmDialog for both Split Tunnel and DNS & Rules", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    // 1. Split Tunnel dirty-tab ConfirmDialog
    fireEvent.click(getNavButton(/Split Tunnel/i));
    await screen.findByRole("heading", { name: "Split Tunneling" });
    await screen.findByText("Google Chrome");

    fireEvent.click(
      screen.getByRole("switch", { name: /Exclude Google Chrome \(chrome\.exe\)/i }),
    );
    expect(
      screen.getByRole("region", { name: "Unsaved Changes" }),
    ).toBeInTheDocument();

    // Attempt to leave -> ConfirmDialog intercepts
    fireEvent.click(getNavButton("Overview"));
    const splitDialog = await screen.findByRole("alertdialog", {
      name: "Discard unsaved split tunnel changes?",
    });
    // Stay keeps us on Split Tunneling
    fireEvent.click(within(splitDialog).getByRole("button", { name: "Stay" }));
    await waitFor(() => {
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    });
    expect(
      screen.getByRole("heading", { name: "Split Tunneling" }),
    ).toBeInTheDocument();

    // Leave again and confirm Discard & Leave
    fireEvent.click(getNavButton("Overview"));
    const splitDialogConfirm = await screen.findByRole("alertdialog", {
      name: "Discard unsaved split tunnel changes?",
    });
    fireEvent.click(
      within(splitDialogConfirm).getByRole("button", {
        name: "Discard & Leave",
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "Protected" }),
    ).toBeInTheDocument();

    // 2. DNS & Rules dirty-tab ConfirmDialog
    fireEvent.click(getNavButton("DNS & Rules"));
    await screen.findByRole("heading", { name: "DNS & Rules" });

    fireEvent.click(screen.getByRole("radio", { name: /Quad9/i }));
    expect(
      screen.getByRole("region", { name: "Unsaved DNS and rule changes" }),
    ).toBeInTheDocument();

    // Attempt to leave -> ConfirmDialog intercepts
    fireEvent.click(getNavButton("Overview"));
    const dnsDialog = await screen.findByRole("alertdialog", {
      name: "Discard unsaved DNS & Rules changes?",
    });
    // Stay keeps us on DNS & Rules
    fireEvent.click(within(dnsDialog).getByRole("button", { name: "Stay" }));
    await waitFor(() => {
      expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    });
    expect(
      screen.getByRole("heading", { name: "DNS & Rules" }),
    ).toBeInTheDocument();

    // Leave again and confirm Discard & Leave
    fireEvent.click(getNavButton("Overview"));
    const dnsDialogConfirm = await screen.findByRole("alertdialog", {
      name: "Discard unsaved DNS & Rules changes?",
    });
    fireEvent.click(
      within(dnsDialogConfirm).getByRole("button", {
        name: "Discard & Leave",
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "Protected" }),
    ).toBeInTheDocument();
  });

  it("switches to the Settings tab on Cmd+, (metaKey + Comma)", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    expect(getNavButton("Overview")).toHaveAttribute("aria-current", "page");

    fireEvent.keyDown(window, { metaKey: true, code: "Comma" });

    expect(
      await screen.findByRole("heading", { name: "Window & System Tray" }),
    ).toBeInTheDocument();
    expect(getNavButton("Settings")).toHaveAttribute("aria-current", "page");
  });

  it("displays Tray unavailable in Sidebar when traySupported is false and tray prefs are enabled", async () => {
    statusSnapshotOverride = {
      platform: "linux",
      traySupported: false,
    };

    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    const sidebar = screen.getByRole("complementary", {
      name: "Application navigation",
    });
    expect(within(sidebar).getByText("Window only")).toBeInTheDocument();

    fireEvent.click(getNavButton("Settings"));
    await screen.findByRole("heading", { name: "Window & System Tray" });

    const keepInTraySwitch = screen.getByRole("switch", {
      name: "Keep in system tray when closed",
    });
    fireEvent.click(keepInTraySwitch);

    await waitFor(() => {
      expect(keepInTraySwitch).toHaveAttribute("aria-checked", "true");
    });

    expect(within(sidebar).getByText("Tray unavailable")).toBeInTheDocument();
    expect(within(sidebar).queryByText("Window only")).not.toBeInTheDocument();
  });

  it("shows Menu bar wording in Sidebar and Settings on macOS", async () => {
    statusSnapshotOverride = {
      platform: "macos",
      traySupported: true,
    };

    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    const sidebar = screen.getByRole("complementary", {
      name: "Application navigation",
    });

    fireEvent.click(getNavButton("Settings"));
    expect(
      await screen.findByRole("heading", { name: "Window & Menu Bar" }),
    ).toBeInTheDocument();
    expect(screen.getByText("No menu bar icon")).toBeInTheDocument();

    const keepInMenuBarSwitch = screen.getByRole("switch", {
      name: "Keep in menu bar when closed",
    });
    fireEvent.click(keepInMenuBarSwitch);

    await waitFor(() => {
      expect(keepInMenuBarSwitch).toHaveAttribute("aria-checked", "true");
    });

    expect(screen.getByText("Menu bar active")).toBeInTheDocument();
    expect(within(sidebar).getByText("Menu bar")).toBeInTheDocument();
    expect(within(sidebar).queryByText("Tray on")).not.toBeInTheDocument();
  });

  it("manages Proxy/TUN switching, uninstall, and reinstall from the Installation tab", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    fireEvent.click(getNavButton("Installation"));
    expect(
      await screen.findByRole("heading", { name: "Installation" }),
    ).toBeInTheDocument();

    const engineGroup = screen.getByRole("radiogroup", {
      name: "Engine Mode",
    });
    const proxyBtn = within(engineGroup).getByRole("radio", { name: "Proxy" });
    const tunBtn = within(engineGroup).getByRole("radio", { name: "TUN" });
    expect(tunBtn).toHaveAttribute("aria-checked", "true");

    fireEvent.click(proxyBtn);
    const switchDialog = await screen.findByRole("dialog");
    fireEvent.click(
      within(switchDialog).getByRole("button", { name: /Switch/i }),
    );
    await waitFor(() => {
      expect(proxyBtn).toHaveAttribute("aria-checked", "true");
    });

    // Uninstall -> transitions to first-run setup UI
    fireEvent.click(screen.getByRole("button", { name: "Uninstall Service" }));
    const uninstallDialog = await screen.findByRole("alertdialog", {
      name: "Uninstall vdpi service?",
    });
    fireEvent.click(
      within(uninstallDialog).getByRole("button", { name: "Uninstall Service" }),
    );

    expect(
      await screen.findByRole("heading", { name: "Set Up Protection Engine" }),
    ).toBeInTheDocument();

    // Install Proxy Mode from first-run setup
    fireEvent.click(screen.getByRole("button", { name: "Install & Protect" }));
    expect(
      await screen.findByRole("heading", { name: "Engine & Background Service" }),
    ).toBeInTheDocument();
  });

  it("shows the in-app launch update prompt when an older engine is installed and lets user dismiss into the app", async () => {
    statusSnapshotOverride = {
      installedVersion: "0.5.6",
      bundledEngineVersion: "0.6.1",
      cliVersionRelation: "upgrade_available",
    };

    render(<App />);
    const prompt = await screen.findByRole("dialog", {
      name: /Engine update ready/i,
    });
    expect(prompt).toBeInTheDocument();

    fireEvent.click(within(prompt).getByRole("button", { name: "Not Now" }));
    await waitFor(() => {
      expect(
        screen.queryByRole("dialog", { name: /Engine update ready/i }),
      ).not.toBeInTheDocument();
    });

    expect(
      screen.getByRole("heading", { name: "Protected" }),
    ).toBeInTheDocument();
    const sidebar = screen.getByRole("complementary", {
      name: "Application navigation",
    });
    expect(
      within(sidebar).getByRole("button", { name: /Installation/i }),
    ).toBeInTheDocument();
  });

  it("blocks Repair when newer_installed, surfaces readonly DMG banner, and switches live to Türkçe in Settings", async () => {
    statusSnapshotOverride = {
      platform: "macos",
      installedVersion: "0.7.0",
      bundledEngineVersion: "0.6.1",
      cliVersionRelation: "newer_installed",
      runningFromReadonlyDmg: true,
    };

    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    // Top-level read-only DMG guidance is visible even on Overview
    expect(
      screen.getByText(/Applications folder/i),
    ).toBeInTheDocument();

    // Installation disables Repair so vdpi never downgrades v0.7.0 -> v0.6.1
    fireEvent.click(getNavButton("Installation"));
    expect(
      await screen.findByRole("heading", { name: "Installation" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Repair \/ Reinstall/i }),
    ).toBeDisabled();

    // Live language switch to Türkçe in Settings updates the sidebar & view immediately
    fireEvent.click(getNavButton("Settings"));
    const trBtn = await screen.findByRole("radio", { name: "Türkçe" });
    fireEvent.click(trBtn);
    await waitFor(() => {
      const trNav = screen.getByRole("navigation", { name: "Ana gezinme" });
      expect(
        within(trNav).getByRole("button", { name: /Kurulum/i }),
      ).toBeInTheDocument();
    });
  });

  it("releases #root inert and body scroll lock after UpdatePromptDialog -> ConfirmDialog same-commit handoff", async () => {
    let resolveCheckUpdates: ((payload: UpdateCheckPayload) => void) | null =
      null;
    checkUpdatesOverride = () =>
      new Promise<UpdateCheckPayload>((resolve) => {
        resolveCheckUpdates = resolve;
      });

    const rootEl = document.createElement("div");
    rootEl.id = "root";
    document.body.appendChild(rootEl);

    const view = render(<App />, { container: rootEl });
    try {
      await screen.findByRole("heading", { name: "Protected" });

      // Dirty the DNS & Rules tab before the launch update check resolves
      fireEvent.click(getNavButton("DNS & Rules"));
      await screen.findByRole("heading", { name: "DNS & Rules" });
      fireEvent.click(screen.getByRole("radio", { name: /Quad9/i }));
      expect(
        screen.getByRole("region", { name: "Unsaved DNS and rule changes" }),
      ).toBeInTheDocument();

      await waitFor(() => {
        expect(resolveCheckUpdates).not.toBeNull();
      });

      await act(async () => {
        resolveCheckUpdates!({
          currentVersion: "0.6.1",
          latestVersion: "0.7.0",
          hasUpdate: true,
          releaseUrl: "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.7.0",
          releaseNotes: ["Stability improvements"],
        });
      });

      const updateDialog = await screen.findByRole("dialog", {
        name: "Update available",
      });
      expect(rootEl.hasAttribute("inert")).toBe(true);
      expect(document.body.style.overflow).toBe("hidden");

      // Same-commit handoff: closes UpdatePromptDialog and opens dirty-tab ConfirmDialog
      fireEvent.click(
        within(updateDialog).getByRole("button", {
          name: "View in Installation",
        }),
      );

      const confirmDialog = await screen.findByRole("alertdialog", {
        name: "Discard unsaved DNS & Rules changes?",
      });
      expect(
        screen.queryByRole("dialog", { name: "Update available" }),
      ).not.toBeInTheDocument();
      expect(rootEl.hasAttribute("inert")).toBe(true);
      expect(document.body.style.overflow).toBe("hidden");

      // Cancel ConfirmDialog -> both modal locks must be cleanly released
      fireEvent.click(within(confirmDialog).getByRole("button", { name: "Stay" }));
      await waitFor(() => {
        expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
      });

      expect(rootEl.hasAttribute("inert")).toBe(false);
      expect(
        (rootEl as HTMLElement & { inert?: boolean }).inert,
      ).not.toBe(true);
      expect(document.body.style.overflow).not.toBe("hidden");
    } finally {
      view.unmount();
      rootEl.remove();
      document.body.style.overflow = "";
    }
  });

  it("disables TUN segment and shows Wintun hint in Overview on Windows Proxy mode when wintun is not ready", async () => {
    statusSnapshotOverride = (snapshot) => ({
      ...snapshot,
      platform: "windows",
      configuredEngine: "proxy",
      wintun: {
        required: false,
        ready: false,
        message: null,
      },
      live: snapshot.live
        ? {
            ...snapshot.live,
            engine: "proxy",
            mode: "proxy-adaptive",
            socksPort: 11080,
            tunInterface: null,
            physicalNic: null,
          }
        : null,
    });

    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    const engineGroup = screen.getByRole("radiogroup");
    const proxyRadio = within(engineGroup).getByRole("radio", {
      name: "Proxy",
    });
    const tunRadio = within(engineGroup).getByRole("radio", { name: "TUN" });

    expect(proxyRadio).toHaveAttribute("aria-checked", "true");
    expect(tunRadio).toHaveAttribute("aria-checked", "false");
    expect(tunRadio).toBeDisabled();
    expect(
      screen.getByText(
        /Add wintun\.dll to the app folder to enable Full-PC \(TUN\) mode/i,
      ),
    ).toBeInTheDocument();
  });

  it("renders Update cancelled instead of Installation cancelled when an engine upgrade is cancelled", async () => {
    statusSnapshotOverride = {
      installedVersion: "0.5.6",
      bundledEngineVersion: "0.6.1",
      cliVersionRelation: "upgrade_available",
    };
    upgradeServiceOverride = async () => ({
      ok: false,
      cancelled: true,
      message: "Administrator prompt cancelled.",
    });

    render(<App />);
    const prompt = await screen.findByRole("dialog", {
      name: /Engine update ready/i,
    });

    fireEvent.click(
      within(prompt).getByRole("button", { name: "View in Installation" }),
    );
    expect(
      await screen.findByRole("heading", { name: "Installation" }),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /Update Engine to v0\.6\.1/i }),
    );

    expect(await screen.findByText("Update cancelled")).toBeInTheDocument();
    expect(
      screen.queryByText("Installation cancelled"),
    ).not.toBeInTheDocument();
  });

  it("translates Diagnostics check summaries and details in Turkish mode without raw English leaks", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Protected" });

    fireEvent.click(getNavButton("Settings"));
    const trBtn = await screen.findByRole("radio", { name: "Türkçe" });
    fireEvent.click(trBtn);

    const trNav = await screen.findByRole("navigation", {
      name: "Ana gezinme",
    });
    fireEvent.click(within(trNav).getByRole("button", { name: "Tanılama" }));
    await screen.findByRole("heading", { name: "Tanılama" });

    fireEvent.click(
      screen.getByRole("button", { name: "Tanılamayı Çalıştır" }),
    );
    expect(
      await screen.findByText(/Tüm denetimler geçti \(6\/6\)/i),
    ).toBeInTheDocument();

    const resultsCard = screen.getByLabelText("Tanılama denetim sonuçları");
    expect(
      within(resultsCard).getByText("VPN uyumluluğu"),
    ).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Wintun sürücüsü"),
    ).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Şifreli DNS (DoH)"),
    ).toBeInTheDocument();
    expect(
      within(resultsCard).getByText("Çalışma durumu"),
    ).toBeInTheDocument();

    const summaryNodes = resultsCard.querySelectorAll(".diag-check-summary");
    const detailNodes = resultsCard.querySelectorAll(".diag-check-detail");
    expect(summaryNodes.length).toBe(6);
    expect(detailNodes.length).toBeGreaterThanOrEqual(4);
    for (const node of Array.from(summaryNodes)) {
      expect(node.textContent?.trim().length).toBeGreaterThan(0);
    }

    const resultsText = resultsCard.textContent ?? "";
    for (const rawEnglishLeak of [
      "No VPN conflict",
      "Exclude (2 apps)",
      "verified and ready for TUN adapter",
      "Resolved via DoH",
      "QUIC blocking:",
      "TLS 1.3 handshake succeeded",
      "TCP flows",
      "VPN coexistence:",
      "adaptive stage",
      "Engine: TUN",
      "Adapter vdpi-tun0 via",
    ]) {
      expect(resultsText).not.toContain(rawEnglishLeak);
    }
  });
});
