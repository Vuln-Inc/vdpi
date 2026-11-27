import { render, screen, fireEvent, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SplitTunnelView } from "../views/SplitTunnelView";
import type {
  ActionResult,
  DiscoveredAppItem,
  SplitTunnelPayload,
  SplitTunnelPreset,
} from "../types";

const mockGetSplitTunnel = vi.fn<() => Promise<SplitTunnelPayload>>();
const mockSaveSplitTunnel = vi.fn<
  (req: { mode: string; apps: string[]; applyLive: boolean }) => Promise<ActionResult>
>();
const mockPickExecutableFile = vi.fn<() => Promise<string | null>>();

vi.mock("../lib/ipc", () => ({
  getSplitTunnel: () => mockGetSplitTunnel(),
  saveSplitTunnel: (req: { mode: string; apps: string[]; applyLive: boolean }) =>
    mockSaveSplitTunnel(req),
  pickExecutableFile: () => mockPickExecutableFile(),
}));

const PRESETS: SplitTunnelPreset[] = [
  {
    id: "discord",
    label: "Discord",
    description: "Discord stable, PTB, and Canary voice/chat clients",
    apps: ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"],
    groupTag: "communication",
  },
  {
    id: "valorant-riot",
    label: "Valorant & Riot",
    description: "Valorant, Riot Client, and League of Legends",
    apps: [
      "VALORANT.exe",
      "VALORANT-Win64-Shipping.exe",
      "RiotClientServices.exe",
      "RiotClientUx.exe",
      "LeagueClient.exe",
      "League of Legends.exe",
    ],
    groupTag: "games",
  },
  {
    id: "web-browsers",
    label: "Web Browsers",
    description: "Chrome, Edge, and Firefox",
    apps: ["chrome.exe", "msedge.exe", "firefox.exe"],
    groupTag: "browsers",
  },
];

const DISCOVERED_APPS: DiscoveredAppItem[] = [
  {
    displayName: "Discord",
    exeName: "Discord.exe",
    normalizedKey: "discord",
    path: "C:\\Users\\Arda\\AppData\\Local\\Discord\\Discord.exe",
    isRunning: true,
    category: "running",
    companions: ["discordptb", "discordcanary"],
    groupTag: "communication",
  },
  {
    displayName: "Google Chrome",
    exeName: "chrome.exe",
    normalizedKey: "chrome",
    path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    isRunning: true,
    category: "running",
    companions: [],
    groupTag: "browsers",
  },
  {
    displayName: "VALORANT",
    exeName: "VALORANT.exe",
    normalizedKey: "valorant",
    path: "C:\\Riot Games\\VALORANT\\live\\VALORANT.exe",
    isRunning: false,
    category: "installed",
    companions: ["valorant-win64-shipping", "riotclientservices"],
    groupTag: "games",
  },
  {
    displayName: "İstanbul Şarkı Çalar",
    exeName: "sarki-calar.exe",
    normalizedKey: "sarki-calar",
    path: "C:\\Program Files\\Sarki\\sarki-calar.exe",
    isRunning: false,
    category: "installed",
    companions: [],
    groupTag: "media",
  },
];

function makePayload(overrides: Partial<SplitTunnelPayload> = {}): SplitTunnelPayload {
  return {
    mode: "all",
    selectedApps: [],
    discoveredApps: DISCOVERED_APPS,
    presets: PRESETS,
    ...overrides,
  };
}

describe("SplitTunnelView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetSplitTunnel.mockResolvedValue(makePayload());
    mockSaveSplitTunnel.mockResolvedValue({
      ok: true,
      message: "Split tunneling saved and applied.",
      needsRestart: false,
    });
    mockPickExecutableFile.mockResolvedValue(null);
  });

  it("switches between Protect All, Exclude Selected, and Include Only modes", async () => {
    render(<SplitTunnelView />);

    await screen.findByText("Google Chrome");

    const modeGroup = screen.getByRole("radiogroup", {
      name: "Split tunneling mode",
    });
    const protectAll = within(modeGroup).getByRole("radio", {
      name: /Protect All Apps/i,
    });
    const excludeSelected = within(modeGroup).getByRole("radio", {
      name: /Exclude Selected/i,
    });
    const includeOnly = within(modeGroup).getByRole("radio", {
      name: /Include Only/i,
    });

    expect(protectAll).toHaveAttribute("aria-checked", "true");
    expect(excludeSelected).toHaveAttribute("aria-checked", "false");
    expect(includeOnly).toHaveAttribute("aria-checked", "false");
    expect(
      screen.getByText(/Toggle any app to switch to Exclude Selected/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Clicking a preset switches to Exclude Selected automatically/i),
    ).toBeInTheDocument();

    // Switch to Exclude Selected
    fireEvent.click(excludeSelected);
    expect(excludeSelected).toHaveAttribute("aria-checked", "true");
    expect(protectAll).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText(/0 selected/i)).toBeInTheDocument();

    // Switch to Include Only
    fireEvent.click(includeOnly);
    expect(includeOnly).toHaveAttribute("aria-checked", "true");
    expect(excludeSelected).toHaveAttribute("aria-checked", "false");

    // Switch back to Protect All Apps
    fireEvent.click(protectAll);
    expect(protectAll).toHaveAttribute("aria-checked", "true");
    expect(
      screen.queryByRole("region", { name: "Unsaved Changes" }),
    ).not.toBeInTheDocument();
  });

  it("shows explicit empty Include warning when Include Only has 0 apps and clears it once an app is added", async () => {
    render(<SplitTunnelView />);
    await screen.findByText("Discord");

    const includeOnly = screen.getByRole("radio", { name: /Include Only/i });
    fireEvent.click(includeOnly);

    const warning = screen.getByRole("status");
    expect(warning).toHaveTextContent(/0 apps selected/i);
    expect(warning).toHaveTextContent(
      /no apps will be protected until you add at least one/i,
    );

    // Toggle Discord on — warning should disappear
    const discordSwitch = screen.getByRole("switch", {
      name: /Include Discord \(Discord\.exe\)/i,
    });
    fireEvent.click(discordSwitch);

    expect(
      screen.queryByText(/0 apps selected/i),
    ).not.toBeInTheDocument();
  });

  it("toggles Quick Presets for Discord and Valorant & Riot", async () => {
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: [] }),
    );
    render(<SplitTunnelView />);
    await screen.findByText("Discord");

    const presetsGroup = screen.getByRole("group", { name: "App presets" });
    const discordPreset = within(presetsGroup).getByRole("button", {
      name: /^Discord$/i,
    });
    const valorantPreset = within(presetsGroup).getByRole("button", {
      name: /Valorant & Riot/i,
    });

    expect(discordPreset).toHaveAttribute("aria-pressed", "false");
    expect(valorantPreset).toHaveAttribute("aria-pressed", "false");

    // Click Discord preset (3 apps)
    fireEvent.click(discordPreset);
    expect(discordPreset).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("3 selected")).toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: /Exclude Discord \(Discord\.exe\)/i }),
    ).toHaveAttribute("aria-checked", "true");

    // Click Valorant & Riot preset (6 apps, total 9)
    fireEvent.click(valorantPreset);
    expect(valorantPreset).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("9 selected")).toBeInTheDocument();
    expect(
      screen.getByRole("switch", { name: /Exclude VALORANT \(VALORANT\.exe\)/i }),
    ).toHaveAttribute("aria-checked", "true");

    const unsavedBar = screen.getByRole("region", { name: "Unsaved Changes" });
    expect(within(unsavedBar).getByText("+9 added")).toBeInTheDocument();

    // Clicking Discord preset again deselects its 3 apps
    fireEvent.click(discordPreset);
    expect(discordPreset).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByText("6 selected")).toBeInTheDocument();
  });

  it("supports Turkish-aware search filtering across dotted/dotless I and diacritics", async () => {
    render(<SplitTunnelView />);
    await screen.findByText("İstanbul Şarkı Çalar");

    const searchBox = screen.getByRole("searchbox", {
      name: "Search applications",
    });
    const getAppList = () =>
      screen.getByRole("list", { name: "Split tunneling applications" });

    // Turkish uppercase dotted İ matches ASCII "Discord"
    fireEvent.change(searchBox, { target: { value: "DİSCORD" } });
    expect(within(getAppList()).getByText("Discord")).toBeInTheDocument();
    expect(
      within(getAppList()).queryByText("Google Chrome"),
    ).not.toBeInTheDocument();
    expect(
      within(getAppList()).queryByText("İstanbul Şarkı Çalar"),
    ).not.toBeInTheDocument();

    // ASCII "istanbul sarki" matches "İstanbul Şarkı Çalar"
    fireEvent.change(searchBox, { target: { value: "istanbul sarki" } });
    expect(
      within(getAppList()).getByText("İstanbul Şarkı Çalar"),
    ).toBeInTheDocument();
    expect(within(getAppList()).queryByText("Discord")).not.toBeInTheDocument();

    // Dotless lowercase ı matches ASCII i in "Discord"
    fireEvent.change(searchBox, { target: { value: "dıscord" } });
    expect(within(getAppList()).getByText("Discord")).toBeInTheDocument();
    expect(
      within(getAppList()).queryByText("İstanbul Şarkı Çalar"),
    ).not.toBeInTheDocument();

    // Clear search restores full list
    fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
    expect(within(getAppList()).getByText("Google Chrome")).toBeInTheDocument();
    expect(
      within(getAppList()).getByText("İstanbul Şarkı Çalar"),
    ).toBeInTheDocument();
  });

  it("adds custom executables from raw name or quoted shortcut path via disclosure toggle", async () => {
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: [] }),
    );
    render(<SplitTunnelView />);
    await screen.findByText("Discord");

    // Custom app form is collapsed by default behind the disclosure button
    expect(
      screen.queryByRole("textbox", {
        name: "Add custom app executable or shortcut command",
      }),
    ).not.toBeInTheDocument();

    const disclosureBtn = screen.getByRole("button", {
      name: /Add custom app/i,
    });
    expect(disclosureBtn).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(disclosureBtn);
    expect(disclosureBtn).toHaveAttribute("aria-expanded", "true");

    const customInput = screen.getByRole("textbox", {
      name: "Add custom app executable or shortcut command",
    });
    const addButton = screen.getByRole("button", { name: "Add" });

    expect(addButton).toBeDisabled();

    fireEvent.change(customInput, {
      target: { value: '"C:\\Games\\Studio\\my-custom-game.exe" --fullscreen' },
    });
    expect(addButton).toBeEnabled();
    fireEvent.click(addButton);

    expect(customInput).toHaveValue("");
    expect(screen.getByText("my-custom-game.exe")).toBeInTheDocument();
    expect(
      screen.getByRole("switch", {
        name: /Exclude My Custom Game \(my-custom-game\.exe\)/i,
      }),
    ).toHaveAttribute("aria-checked", "true");

    // Invalid executable input displays validation error
    fireEvent.change(customInput, { target: { value: ".." } });
    fireEvent.click(addButton);
    expect(
      screen.getByText(/Enter a valid executable name or path/i),
    ).toBeInTheDocument();

    // Clicking the disclosure toggle again collapses the custom app form
    fireEvent.click(disclosureBtn);
    expect(disclosureBtn).toHaveAttribute("aria-expanded", "false");
    expect(
      screen.queryByRole("textbox", {
        name: "Add custom app executable or shortcut command",
      }),
    ).not.toBeInTheDocument();
  });

  it("handles Sticky Unsaved Changes bar Discard and Save & Apply flows", async () => {
    const onSaved = vi.fn();
    const onPushToast = vi.fn();
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: ["chrome.exe"] }),
    );

    render(<SplitTunnelView onSaved={onSaved} onPushToast={onPushToast} />);
    await screen.findByText("Google Chrome");

    // Clean initially
    expect(
      screen.queryByRole("region", { name: "Unsaved Changes" }),
    ).not.toBeInTheDocument();

    // Make changes: switch to Include Only + select Discord
    fireEvent.click(screen.getByRole("radio", { name: /Include Only/i }));
    fireEvent.click(
      screen.getByRole("switch", { name: /Include Discord \(Discord\.exe\)/i }),
    );

    const unsavedBar = screen.getByRole("region", { name: "Unsaved Changes" });
    expect(within(unsavedBar).getByText("Unsaved Changes")).toBeInTheDocument();
    expect(
      within(unsavedBar).getByText("Mode: Include Only"),
    ).toBeInTheDocument();
    expect(within(unsavedBar).getByText("+1 added")).toBeInTheDocument();

    // Discard reverts draft back to saved state
    fireEvent.click(within(unsavedBar).getByRole("button", { name: "Discard" }));
    expect(
      screen.queryByRole("region", { name: "Unsaved Changes" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("radio", { name: /Exclude Selected/i }),
    ).toHaveAttribute("aria-checked", "true");
    expect(
      screen.getByRole("switch", { name: /Exclude Discord \(Discord\.exe\)/i }),
    ).toHaveAttribute("aria-checked", "false");
    expect(mockSaveSplitTunnel).not.toHaveBeenCalled();

    // Make change again and click Save & Apply
    fireEvent.click(
      screen.getByRole("switch", { name: /Exclude Discord \(Discord\.exe\)/i }),
    );
    const barForSave = screen.getByRole("region", { name: "Unsaved Changes" });
    fireEvent.click(
      within(barForSave).getByRole("button", { name: "Save & Apply" }),
    );

    await waitFor(() => {
      expect(mockSaveSplitTunnel).toHaveBeenCalledTimes(1);
    });
    expect(mockSaveSplitTunnel).toHaveBeenCalledWith({
      mode: "exclude",
      apps: ["chrome.exe", "Discord.exe"],
      applyLive: true,
    });

    await waitFor(() => {
      expect(
        screen.queryByRole("region", { name: "Unsaved Changes" }),
      ).not.toBeInTheDocument();
    });
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(onPushToast).toHaveBeenCalledWith(
      "success",
      "Split tunneling saved and applied.",
    );
  });

  it("supports roving tabIndex and Arrow/Home/End keyboard navigation across routing modes", async () => {
    render(<SplitTunnelView />);
    await screen.findByText("Discord");

    const modeGroup = screen.getByRole("radiogroup", {
      name: "Split tunneling mode",
    });
    const protectAll = within(modeGroup).getByRole("radio", {
      name: /Protect All Apps/i,
    });
    const excludeSelected = within(modeGroup).getByRole("radio", {
      name: /Exclude Selected/i,
    });
    const includeOnly = within(modeGroup).getByRole("radio", {
      name: /Include Only/i,
    });

    expect(protectAll).toHaveAttribute("tabindex", "0");
    expect(excludeSelected).toHaveAttribute("tabindex", "-1");
    expect(includeOnly).toHaveAttribute("tabindex", "-1");

    protectAll.focus();
    fireEvent.keyDown(protectAll, { key: "ArrowRight" });
    expect(excludeSelected).toHaveAttribute("aria-checked", "true");
    expect(excludeSelected).toHaveAttribute("tabindex", "0");
    expect(protectAll).toHaveAttribute("tabindex", "-1");
    expect(excludeSelected).toHaveFocus();

    fireEvent.keyDown(excludeSelected, { key: "ArrowRight" });
    expect(includeOnly).toHaveAttribute("aria-checked", "true");
    expect(includeOnly).toHaveAttribute("tabindex", "0");
    expect(excludeSelected).toHaveAttribute("tabindex", "-1");
    expect(includeOnly).toHaveFocus();

    // Wraps from last back to first
    fireEvent.keyDown(includeOnly, { key: "ArrowRight" });
    expect(protectAll).toHaveAttribute("aria-checked", "true");
    expect(protectAll).toHaveAttribute("tabindex", "0");
    expect(protectAll).toHaveFocus();

    // ArrowLeft wraps from first to last
    fireEvent.keyDown(protectAll, { key: "ArrowLeft" });
    expect(includeOnly).toHaveAttribute("aria-checked", "true");
    expect(includeOnly).toHaveAttribute("tabindex", "0");
    expect(includeOnly).toHaveFocus();

    // Home / End keys
    fireEvent.keyDown(includeOnly, { key: "Home" });
    expect(protectAll).toHaveAttribute("aria-checked", "true");
    expect(protectAll).toHaveFocus();

    fireEvent.keyDown(protectAll, { key: "End" });
    expect(includeOnly).toHaveAttribute("aria-checked", "true");
    expect(includeOnly).toHaveFocus();
  });

  it("keeps app row sort order frozen when toggling an app so rows do not jump under the pointer", async () => {
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: [] }),
    );
    render(<SplitTunnelView />);
    await screen.findByText("VALORANT");

    const getRowKeys = () =>
      within(
        screen.getByRole("list", { name: "Split tunneling applications" }),
      )
        .getAllByRole("listitem")
        .map((row) => row.getAttribute("data-app-key"));

    const initialOrder = getRowKeys();
    expect(initialOrder.length).toBe(DISCOVERED_APPS.length);

    // Toggle a non-running app near the bottom (VALORANT) ON and verify order does not jump
    const valorantSwitch = screen.getByRole("switch", {
      name: /Exclude VALORANT \(VALORANT\.exe\)/i,
    });
    expect(valorantSwitch).toHaveAttribute("aria-checked", "false");
    fireEvent.click(valorantSwitch);
    expect(valorantSwitch).toHaveAttribute("aria-checked", "true");
    expect(getRowKeys()).toEqual(initialOrder);

    // Toggle Turkish app ON as well and verify order stays frozen
    const sarkiSwitch = screen.getByRole("switch", {
      name: /Exclude İstanbul Şarkı Çalar \(sarki-calar\.exe\)/i,
    });
    fireEvent.click(sarkiSwitch);
    expect(sarkiSwitch).toHaveAttribute("aria-checked", "true");
    expect(getRowKeys()).toEqual(initialOrder);
  });

  it("renders Unicode-safe Turkish monogram (İŞ) for non-ASCII app display names", async () => {
    render(<SplitTunnelView />);
    await screen.findByText("İstanbul Şarkı Çalar");

    const list = screen.getByRole("list", {
      name: "Split tunneling applications",
    });
    const rows = within(list).getAllByRole("listitem");
    const turkishRow = rows.find(
      (row) => row.getAttribute("data-app-key") === "sarki-calar",
    );
    expect(turkishRow).toBeDefined();
    expect(
      turkishRow?.querySelector(".split-app-row__monogram"),
    ).toHaveTextContent("İŞ");

    const chromeRow = rows.find(
      (row) => row.getAttribute("data-app-key") === "chrome",
    );
    expect(
      chromeRow?.querySelector(".split-app-row__monogram"),
    ).toHaveTextContent("GC");
  });

  it("saves dirty changes on Ctrl+S when no modal is open and suppresses Ctrl+S while an aria-modal dialog is present", async () => {
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: ["chrome.exe"] }),
    );
    render(<SplitTunnelView />);
    await screen.findByText("Google Chrome");

    // Make draft dirty by toggling Discord on
    fireEvent.click(
      screen.getByRole("switch", { name: /Exclude Discord \(Discord\.exe\)/i }),
    );
    expect(
      screen.getByRole("region", { name: "Unsaved Changes" }),
    ).toBeInTheDocument();

    // Presence of an [aria-modal="true"] element suppresses Ctrl+S
    const modal = document.createElement("div");
    modal.setAttribute("role", "dialog");
    modal.setAttribute("aria-modal", "true");
    document.body.appendChild(modal);
    try {
      fireEvent.keyDown(window, { key: "s", code: "KeyS", ctrlKey: true });
      expect(mockSaveSplitTunnel).not.toHaveBeenCalled();
    } finally {
      modal.remove();
    }

    // Without any modal present, Ctrl+S triggers Save & Apply
    fireEvent.keyDown(window, { key: "s", code: "KeyS", ctrlKey: true });

    await waitFor(() => {
      expect(mockSaveSplitTunnel).toHaveBeenCalledTimes(1);
    });
    expect(mockSaveSplitTunnel).toHaveBeenCalledWith({
      mode: "exclude",
      apps: ["chrome.exe", "Discord.exe"],
      applyLive: true,
    });
    await waitFor(() => {
      expect(
        screen.queryByRole("region", { name: "Unsaved Changes" }),
      ).not.toBeInTheDocument();
    });
  });

  it("displays a shortcut-specific hint error when a .lnk file is entered in custom app input", async () => {
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: [] }),
    );
    render(<SplitTunnelView />);
    await screen.findByText("Discord");

    fireEvent.click(screen.getByRole("button", { name: /Add custom app/i }));
    const customInput = screen.getByRole("textbox", {
      name: "Add custom app executable or shortcut command",
    });
    fireEvent.change(customInput, {
      target: { value: "C:\\Users\\Arda\\Desktop\\Discord.lnk" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(/Windows shortcut \(\.lnk\) files are not supported directly/i);
    expect(alert).toHaveTextContent(/target \.exe file/i);
  });

  it("emits an info toast when adding a custom executable", async () => {
    const onPushToast = vi.fn();
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: [] }),
    );
    render(<SplitTunnelView onPushToast={onPushToast} />);
    await screen.findByText("Discord");

    fireEvent.click(screen.getByRole("button", { name: /Add custom app/i }));
    const customInput = screen.getByRole("textbox", {
      name: "Add custom app executable or shortcut command",
    });
    fireEvent.change(customInput, {
      target: { value: "my-custom-app.exe" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(onPushToast).toHaveBeenCalledWith("info", "Added my-custom-app.exe");
  });

  it("displays N / 256 selected when >= 200 apps are selected and blocks adding a 257th app", async () => {
    const onPushToast = vi.fn();
    const initial200 = Array.from(
      { length: 200 },
      (_, idx) => `bulk-app-${idx + 1}.exe`,
    );
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: initial200 }),
    );
    const { unmount } = render(<SplitTunnelView onPushToast={onPushToast} />);
    await screen.findByText("Discord");

    expect(screen.getByText("200 / 256 selected")).toBeInTheDocument();
    unmount();

    // At the 256 cap, adding a 257th app via row toggle or custom input is blocked
    const full256 = Array.from(
      { length: 256 },
      (_, idx) => `bulk-app-${idx + 1}.exe`,
    );
    mockGetSplitTunnel.mockResolvedValue(
      makePayload({ mode: "exclude", selectedApps: full256 }),
    );
    render(<SplitTunnelView onPushToast={onPushToast} />);
    await screen.findByText("Discord");

    expect(screen.getByText("256 / 256 selected")).toBeInTheDocument();

    const discordSwitch = screen.getByRole("switch", {
      name: /Exclude Discord \(Discord\.exe\)/i,
    });
    expect(discordSwitch).toHaveAttribute("aria-checked", "false");
    fireEvent.click(discordSwitch);

    expect(discordSwitch).toHaveAttribute("aria-checked", "false");
    expect(screen.getByText("256 / 256 selected")).toBeInTheDocument();
    expect(onPushToast).toHaveBeenCalledWith(
      "warn",
      expect.stringMatching(/Maximum 256 apps allowed/i),
    );

    fireEvent.click(screen.getByRole("button", { name: /Add custom app/i }));
    const customInput = screen.getByRole("textbox", {
      name: "Add custom app executable or shortcut command",
    });
    fireEvent.change(customInput, {
      target: { value: "overflow-app-257.exe" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(screen.getByText("256 / 256 selected")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(
      /Maximum 256 apps allowed/i,
    );
  });
});
