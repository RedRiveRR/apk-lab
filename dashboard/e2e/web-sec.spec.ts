import { expect, test, type Page } from "@playwright/test";
import type { WebSecCompare, WebSecGuides, WebSecJob, WebSecModule, WebSecMonitorConfig, WebSecMonitorStatus, WebSecPreferences, WebSecReport, WebSecStatus } from "../src/lib/api";

const status: WebSecStatus = {
  state: "ready",
  provider: "native-python",
  requirements: [
    { id: "python", label: "Python 3.9+", found: true, required: true, hint: "" },
    { id: "storage", label: "Writable Web Sec Lab storage", found: true, required: true, hint: "" },
    { id: "scope", label: "Declared test scope", found: true, required: true, hint: "" }
  ],
  reasons: [],
  notes: ["Scope “websec-test” covers 1 host rule(s) and expires 2099-01-01."],
  version: "0.1.0",
  python: "/usr/bin/python3",
  storage: "/tmp/websec/storage"
};

const modules: WebSecModule[] = [
  { id: "dns_records", label: "DNS records", description: "", group: "recon", weight: "light", active: false, upstream: "DNS Records" },
  { id: "port_exposure", label: "Port exposure", description: "", group: "security", weight: "heavy", active: true, upstream: "Nmap Zero Day Scan" }
];

const report: WebSecReport = {
  target: "example.test",
  url: "https://example.test",
  started_at: "2026-11-24T00:00:00+00:00",
  duration_seconds: 1.2,
  preset: "standard",
  active: true,
  score: 95,
  grade: "A",
  summary: { critical: 0, high: 0, medium: 1, low: 0, info: 0, total: 1 },
  refused: false,
  refusal: "",
  modules: [{ id: "security_analysis", label: "Security posture", status: "ok", duration_ms: 120, findings: 1, error: "", note: "" }],
  findings: [
    {
      module: "security_analysis",
      severity: "medium",
      title: "Content-Security-Policy is missing",
      detail: "Nothing limits which scripts the page may load.",
      evidence: "",
      remediation: "Send a policy that allows script-src 'self'.",
      refs: []
    }
  ]
};

const defaults: WebSecPreferences = {
  scan: { target: "", preset: "standard", scheme: "https", modules: [], timeout: null, deadline: null },
  bulk: { preset: "quick" }
};

const guides: WebSecGuides = {
  guides: [
    { id: "scope", title: "Scope and authorization", checks: [], points: ["Scan only hosts listed in scope.json, and only with written permission from their owner."], refs: [] },
    { id: "headers", title: "Security headers and cookies", checks: ["security_analysis"], points: ["Mark session cookies Secure, HttpOnly and SameSite."], refs: ["https://owasp.org/www-project-secure-headers/"] }
  ],
  byCheck: { security_analysis: "headers" },
  reference: {
    ports: [{ port: 6379, service: "Redis", kind: "database" }],
    headers: [{ header: "Strict-Transport-Security", expect: "Present on HTTPS, max-age of at least 180 days, includeSubDomains." }]
  }
};

const monitorOff: WebSecMonitorStatus = {
  config: { enabled: false, targets: [], intervalMinutes: 1440, preset: "quick", alertOn: "high", notify: true, reminderHours: 24, scopeWarnDays: 14 },
  configError: null, targets: {}, activeWarnings: [], events: [], intervals: [60, 360, 1440, 10080],
  runner: { alive: true, running: false, lastTick: { at: 0, error: "", events: 0, scanned: 0 } }
};

const job = (state: WebSecJob["state"], extra: Partial<WebSecJob> = {}): WebSecJob => ({
  id: "scan-1", state, target: "example.test", preset: "standard", active: true, started: 1, ...extra
});

/** Status, catalogue, empty history and reports, saved choices (GET + POST) and guides. */
async function mockStatus(page: Page, value: WebSecStatus, saved: WebSecPreferences = defaults) {
  const posted: WebSecPreferences[] = [];
  await page.route("**/api/websec/status", (route) => route.fulfill({ json: value }));
  await page.route("**/api/websec/modules", (route) => route.fulfill({ json: { modules } }));
  await page.route("**/api/websec/history*", (route) => route.fulfill({ json: { entries: [] } }));
  await page.route("**/api/websec/reports*", (route) => route.fulfill({ json: { reports: [] } }));
  await page.route("**/api/websec/guides", (route) => route.fulfill({ json: guides }));
  await page.route("**/api/websec/monitor", (route) => route.fulfill({ json: monitorOff }));
  await page.route("**/api/websec/runs/stats", (route) => route.fulfill({ json: {
    targets: 0, runs: 0, reports: 0, bytes: 0, favourites: 0, grades: {}, latestFindings: {}, latest: [] } }));
  await page.route("**/api/websec/preferences", (route) => {
    if (route.request().method() === "POST") {
      const body = route.request().postDataJSON() as WebSecPreferences;
      posted.push(body);
      return route.fulfill({ json: { preferences: body, configError: null, version: 1 } });
    }
    return route.fulfill({ json: { preferences: saved, configError: null, version: 1 } });
  });
  return posted;
}

/** Open one collapsed row of the options list by its title. */
async function openRow(page: Page, title: string) {
  await page.getByRole("main").locator("details > summary").filter({ has: page.getByText(title, { exact: true }) }).click();
}

/** A scan that is running on the first poll and done with `value` on the second. */
async function mockScan(page: Page, value: WebSecReport = report) {
  const sent: Record<string, unknown>[] = [];
  let polls = 0;
  await page.route(/\/api\/websec\/scans$/, async (route) => {
    sent.push(route.request().postDataJSON());
    return route.fulfill({ status: 202, json: job("running") });
  });
  await page.route(/\/api\/websec\/scans\/scan-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? job("running") : job("done", { report: value }) });
  });
  return sent;
}

test("a ready lab scans a target and shows the graded report", async ({ page }) => {
  await mockStatus(page, status);
  const sent = await mockScan(page);
  await page.route("**/api/websec/history*", (route) => route.fulfill({
    json: { entries: [{ target: "example.test", scanned_at: "2026-11-24T00:00:00+00:00", grade: "A", score: 95, summary: { total: 1 } }] }
  }));

  await page.goto("/web-sec/");
  await expect(page.getByRole("main").getByRole("heading", { name: "Web Sec Lab" })).toBeVisible();
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByLabel("Allow intrusive checks").check();
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("dialog").getByText("Port exposure")).toBeVisible();
  await expect(page.getByRole("dialog").getByText("websec-test")).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Run with intrusive checks" }).click();

  await expect(page.getByRole("main").getByText("Content-Security-Policy is missing")).toBeVisible();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  await expect(page.getByRole("main").getByText("example.test", { exact: true }).first()).toBeVisible();
  expect(sent[0]).toMatchObject({ target: "example.test", preset: "standard", scheme: "https", active: true });
});

test("a lab without a scope disables scanning and explains why", async ({ page }) => {
  const needsSetup: WebSecStatus = {
    ...status,
    state: "needs-setup",
    provider: null,
    reasons: ["Copy console/scope.example.json to scope.json and list the hosts you own."],
    notes: []
  };
  await mockStatus(page, needsSetup);
  await page.goto("/web-sec/");
  await expect(page.getByRole("main").getByText("Needs setup")).toBeVisible();
  await expect(page.getByRole("main").getByText("Copy console/scope.example.json to scope.json and list the hosts you own.")).toBeVisible();
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await expect(page.getByRole("main").getByRole("button", { name: "Scan", exact: true })).toBeDisabled();
  await expect(page.getByRole("main").getByRole("link", { name: "Status" })).toHaveAttribute("href", "/labs/websec/");
});

test("a stored report opens as rendered Markdown", async ({ page }) => {
  await mockStatus(page, status);
  await page.route("**/api/websec/reports*", (route) => route.fulfill({
    json: { reports: [{ name: "20261124T000000Z-95.json", bytes: 2048, modified: 1 }] }
  }));
  await page.route("**/api/websec/report?*", (route) => route.fulfill({
    json: { content: "# Web Sec Lab report — example.test", format: "markdown", name: "20261124T000000Z-95.json" }
  }));
  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await openRow(page, "Reports");
  await expect(page.getByRole("main").getByText("20261124T000000Z-95.json")).toBeVisible();
  await page.getByRole("main").getByRole("button", { name: "Open" }).click();
  await expect(page.getByRole("main").getByText("# Web Sec Lab report — example.test")).toBeVisible();
});

const reportWithModuleData: WebSecReport = {
  ...report,
  modules: [
    {
      id: "domain_info", label: "Domain information", status: "ok", duration_ms: 90,
      findings: 0, error: "", note: "",
      data: {
        "domain name": ["example.test"],
        registrar: ["TEST Registrar"],
        "registry expiry date": ["2027-01-01T00:00:00Z"],
        "name server": ["ns1.example.test", "ns2.example.test"],
        status: ["ok"],
        available: true
      }
    },
    {
      id: "security_analysis", label: "Security posture", status: "ok", duration_ms: 120,
      findings: 1, error: "", note: "",
      data: {
        score: 82,
        grade: "B",
        headers: { "strict-transport-security": "max-age=63072000; includeSubDomains" },
        cookies: [{ name: "sid", secure: true, httponly: true, samesite: "Lax", session: true }],
        https_redirect: true,
        checks: []
      }
    }
  ]
};

test("check rows open drill-down panels with the module's own data", async ({ page }) => {
  await mockStatus(page, status);
  await mockScan(page, reportWithModuleData);

  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  await page.getByRole("main").locator("summary").filter({ hasText: /^Checks$/ }).click();

  const whoisToggle = page.getByRole("main").getByRole("button", { name: "Domain information" });
  await expect(whoisToggle).toHaveAttribute("aria-expanded", "false");
  await whoisToggle.click();
  await expect(whoisToggle).toHaveAttribute("aria-expanded", "true");
  const whoisRegion = page.getByRole("region", { name: "Domain information details" });
  await expect(whoisRegion).toBeVisible();
  await expect(whoisRegion.getByText("TEST Registrar")).toBeVisible();
  await expect(whoisRegion.getByText("ns1.example.test")).toBeVisible();

  const headersToggle = page.getByRole("main").getByRole("button", { name: "Security posture", exact: true });
  await headersToggle.click();
  const headersRegion = page.getByRole("region", { name: "Security posture details" });
  await expect(headersRegion).toBeVisible();
  await expect(headersRegion.getByText("strict-transport-security")).toBeVisible();
  await expect(headersRegion.getByText("sid")).toBeVisible();
  await expect(headersRegion.getByText("Redirects to https")).toBeVisible();
});

test("stored reports download in every format with the right file name", async ({ page }) => {
  await mockStatus(page, status);
  await page.route("**/api/websec/reports*", (route) => route.fulfill({
    json: { reports: [{ name: "20261124T000000Z-95.json", bytes: 2048, modified: 1 }] }
  }));
  const formats: string[] = [];
  await page.route("**/api/websec/report?*", (route) => {
    const format = new URL(route.request().url()).searchParams.get("format") ?? "";
    formats.push(format);
    const binary = format === "pdf" || format === "docx";
    return route.fulfill({ json: { content: binary ? Buffer.from(`%${format}`).toString("base64") : `content-${format}`,
      format, name: "20261124T000000Z-95.json", ...(binary ? { encoding: "base64" } : {}) } });
  });

  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await openRow(page, "Reports");
  await expect(page.getByRole("main").getByText("20261124T000000Z-95.json")).toBeVisible();

  for (const [button, extension] of [
    ["JSON", "json"],
    ["SARIF", "sarif"],
    ["HTML", "html"],
    ["Markdown", "md"],
    ["PDF", "pdf"],
    ["DOCX", "docx"]
  ] as const) {
    const pending = page.waitForEvent("download");
    await page.getByRole("main").getByRole("button", { name: button, exact: true }).click();
    const download = await pending;
    expect(download.suggestedFilename()).toBe(`example.test.20261124T000000Z-95.${extension}`);
  }
  expect(formats).toEqual(["json", "sarif", "html", "markdown", "pdf", "docx"]);

  await page.getByRole("main").getByRole("button", { name: "Open" }).click();
  await expect(page.getByRole("main").getByText("content-markdown")).toBeVisible();
});

test("a bulk job renders a grade per target and a refusal row", async ({ page }) => {
  await mockStatus(page, status);
  let sent: Record<string, unknown> | null = null;
  await page.route("**/api/websec/bulk", async (route) => {
    sent = route.request().postDataJSON();
    return route.fulfill({ status: 202, json: {
      id: "bulk-1", state: "running", kind: "bulk", target: "", preset: "quick", active: false, started: 1
    } });
  });
  let polls = 0;
  const bulkDone = {
    id: "bulk-1", state: "done", kind: "bulk", target: "", preset: "quick", active: false, started: 1,
    results: {
      count: 4,
      targets: [
        { target: "one.test", grade: "A", score: 96, summary: { total: 1 }, error: "" },
        { target: "two.test", grade: "B", score: 84, summary: { total: 2 }, error: "" },
        { target: "three.test", grade: "C", score: 72, summary: { total: 3 }, error: "" },
        { target: "outside.test", grade: "", score: 0, summary: {}, error: "the target is outside the declared scope" }
      ]
    }
  };
  await page.route(/\/api\/websec\/bulk\/bulk-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? { ...bulkDone, state: "running", results: undefined } : bulkDone });
  });

  await page.goto("/web-sec/");
  await openRow(page, "Bulk validation");
  await page.getByRole("main").getByLabel("Targets file").setInputFiles({
    name: "targets.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("# owned hosts\none.test\ntwo.test, comment\nthree.test\noutside.test\n")
  });
  await page.getByRole("main").getByRole("button", { name: "Validate" }).click();

  await expect(page.getByRole("main").getByText("one.test")).toBeVisible();
  await expect(page.getByRole("main").getByText("outside.test")).toBeVisible();
  await expect(page.getByRole("main").getByText("the target is outside the declared scope")).toBeVisible();
  await expect(page.getByRole("main").getByText("three.test")).toBeVisible();
  expect(sent).toMatchObject({ targets: ["one.test", "two.test", "three.test", "outside.test"], preset: "quick" });
});

test("pacing overrides ride along with the scan request", async ({ page }) => {
  await mockStatus(page, status);
  const sent = await mockScan(page);

  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await openRow(page, "Scan options");
  await page.getByRole("main").getByLabel("Request timeout (s)").fill("12");
  await page.getByRole("main").getByLabel("Scan budget (s)").fill("120");
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  expect(sent[0]).toMatchObject({ target: "example.test", timeout: 12, deadline: 120 });
});

test("a history row opens the stored report in the workbench", async ({ page }) => {
  await mockStatus(page, status);
  await page.route("**/api/websec/history*", (route) => route.fulfill({
    json: { entries: [{
      target: "example.test", scanned_at: "2026-11-24T00:00:00+00:00", grade: "A", score: 95,
      summary: { total: 1 }, preset: "standard", active: false, refused: false,
      name: "20261124T000000Z-95.json"
    }] }
  }));
  await page.route("**/api/websec/report?*", (route) => route.fulfill({
    json: { content: JSON.stringify(reportWithModuleData), format: "json", name: "20261124T000000Z-95.json" }
  }));

  await page.goto("/web-sec/");
  await openRow(page, "History");
  await expect(page.getByRole("main").getByText("2026-11-24T00:00:00+00:00")).toBeVisible();
  await page.getByRole("main").getByRole("button", { name: "Open" }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  await expect(page.getByRole("main").getByText("Content-Security-Policy is missing")).toBeVisible();
  // a stored report is not a running scan: no live progress rows
  await expect(page.getByRole("main").getByText("pending", { exact: true })).toHaveCount(0);
});

test("a running scan shows live per-check progress", async ({ page }) => {
  await mockStatus(page, status);
  let polls = 0;
  const runningJob = { ...job("running"), progress: {
    modules: [{ id: "dns_records", status: "ok" }, { id: "security_analysis", status: null }]
  } };
  await page.route(/\/api\/websec\/scans$/, (route) => route.fulfill({ status: 202, json: runningJob }));
  await page.route(/\/api\/websec\/scans\/scan-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? runningJob : job("done", { report }) });
  });

  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("DNS records")).toBeVisible();
  await expect(page.getByRole("main").getByText("running", { exact: true })).toBeVisible();
  await expect(page.getByRole("main").getByText("security_analysis")).toBeVisible();
  await expect(page.getByRole("main").getByText("Content-Security-Policy is missing")).toBeVisible();
});

test("saved choices load from the engine store and every change is written back", async ({ page }) => {
  const saved: WebSecPreferences = {
    scan: { target: "saved.test", preset: "quick", scheme: "http", modules: ["dns_records", "retired_check"], timeout: 12, deadline: null },
    bulk: { preset: "standard" }
  };
  const posted = await mockStatus(page, status, saved);
  const sent = await mockScan(page);

  await page.goto("/web-sec/");
  await expect(page.getByRole("main").getByRole("textbox", { name: "Target" })).toHaveValue("saved.test");
  await openRow(page, "Scan options");
  await expect(page.getByRole("main").getByLabel("Preset", { exact: true })).toHaveValue("quick");
  await expect(page.getByRole("main").getByLabel("Request timeout (s)")).toHaveValue("12");
  expect(posted).toHaveLength(0); // loading is not a change

  await page.getByRole("main").getByLabel("Preset", { exact: true }).selectOption("full");
  await expect(page.getByRole("main").getByText("Saved on this computer")).toBeVisible();
  // an id the catalogue no longer lists is kept in the store, never deleted
  expect(posted.at(-1)).toMatchObject({ scan: { preset: "full", modules: ["dns_records", "retired_check"] }, bulk: { preset: "standard" } });

  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  // ...but only catalogue ids are sent with a scan, and intrusive mode is never a saved choice
  expect(sent[0]).toMatchObject({ target: "saved.test", preset: "full", scheme: "http", modules: ["dns_records"], active: false });
  expect(JSON.stringify(posted)).not.toContain("active");
});

test("the S key starts a scan, but not while typing", async ({ page }) => {
  await mockStatus(page, status);
  const sent = await mockScan(page);
  await page.goto("/web-sec/");
  const input = page.getByRole("main").getByRole("textbox", { name: "Target" });
  await input.fill("example.test");
  await input.press("s");
  await expect(input).toHaveValue("example.tests");
  expect(sent).toHaveLength(0);
  await input.fill("example.test");
  await expect(page.getByRole("main").getByRole("button", { name: "Scan", exact: true })).toHaveAttribute("aria-keyshortcuts", "S");
  await page.getByRole("main").getByRole("heading", { name: "Web Sec Lab" }).click();
  await page.keyboard.press("s");
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  expect(sent).toHaveLength(1);
});

const diff: WebSecCompare = {
  target: "example.test",
  score: { current: 95, previous: 80, delta: 15 },
  grade: { current: "A", previous: "B" },
  summary: {
    critical: { current: 0, previous: 0 }, high: { current: 0, previous: 1 }, medium: { current: 1, previous: 0 },
    low: { current: 0, previous: 0 }, info: { current: 0, previous: 0 }, total: { current: 1, previous: 1 }
  },
  new: [{ module: "security_analysis", severity: "medium", title: "Content-Security-Policy is missing" }],
  resolved: [{ module: "security_analysis", severity: "high", title: "HSTS is missing" }],
  modules: [{ id: "security_analysis", previous: "error", current: "ok" }],
  from: { name: "20261101T000000Z-80.json" },
  to: { name: "20261124T000000Z-95.json" }
};

test("compare shows a run-to-run diff, from the row and from a history entry", async ({ page }) => {
  await mockStatus(page, status);
  const runs = [
    { name: "20261124T000000Z-95.json", bytes: 2048, modified: 2 },
    { name: "20261101T000000Z-80.json", bytes: 2048, modified: 1 }
  ];
  await page.route("**/api/websec/reports*", (route) => route.fulfill({ json: { reports: runs } }));
  await page.route("**/api/websec/history*", (route) => route.fulfill({ json: { entries: [
    { target: "example.test", scanned_at: "2026-11-24T00:00:00+00:00", grade: "A", score: 95, summary: { total: 1 }, preset: "standard", active: false, refused: false, name: runs[0].name },
    { target: "example.test", scanned_at: "2026-11-01T00:00:00+00:00", grade: "B", score: 80, summary: { total: 1 }, preset: "standard", active: false, refused: false, name: runs[1].name }
  ] } }));
  const asked: { old: string | null; new: string | null }[] = [];
  await page.route("**/api/websec/compare?*", (route) => {
    const url = new URL(route.request().url());
    asked.push({ old: url.searchParams.get("old"), new: url.searchParams.get("new") });
    return route.fulfill({ json: diff });
  });

  await page.goto("/web-sec/");
  // the default target comes from the latest history entry, and compare defaults to the latest two runs
  await expect(page.getByRole("main").getByRole("textbox", { name: "Target" })).toHaveValue("example.test");
  const summary = page.getByRole("main").locator("#websec-compare > summary");
  await expect(summary).toContainText("B → A");
  await openRow(page, "Compare runs");
  const region = page.getByRole("region", { name: "Run comparison" });
  await expect(region.getByText("80 → 95 (+15)")).toBeVisible();
  await expect(region.getByText("Content-Security-Policy is missing")).toBeVisible();
  await expect(region.getByText("HSTS is missing")).toBeVisible();
  expect(asked[0]).toEqual({ old: runs[1].name, new: runs[0].name });

  await openRow(page, "History");
  await page.getByRole("main").getByRole("button", { name: "Compare", exact: true }).click();
  await expect(region).toBeVisible();
  expect(asked.at(-1)).toEqual({ old: runs[1].name, new: runs[0].name });
});

test("SecOps guides open as a modal from a check and from the header", async ({ page }) => {
  await mockStatus(page, status);
  await mockScan(page);
  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();

  // from the finding: straight to the guide that explains its check
  await page.getByRole("main").getByRole("button", { name: "Guide", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Security headers and cookies" })).toBeVisible();
  await expect(dialog.getByText("Mark session cookies Secure, HttpOnly and SameSite.")).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Scope and authorization" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);

  // from the header: every guide
  await page.getByRole("main").getByRole("button", { name: "SecOps guides" }).click();
  await expect(dialog.getByRole("heading", { name: "Scope and authorization" })).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Security headers and cookies" })).toBeVisible();
  await dialog.getByRole("button", { name: "Reference" }).click();
  await expect(dialog.getByRole("cell", { name: "Strict-Transport-Security" })).toBeVisible();
  await expect(dialog.getByRole("cell", { name: "Redis" })).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Scope and authorization" })).toHaveCount(0);
});

test("every workbench ability is still listed and each row opens", async ({ page }) => {
  await mockStatus(page, status);
  await page.goto("/web-sec/");
  await expect(page.getByRole("main").getByRole("button", { name: "Scan", exact: true })).toBeVisible();
  await expect(page.getByRole("main").getByLabel("Allow intrusive checks")).toBeVisible();
  const rows: [string, string][] = [
    ["Scan options", "Request timeout (s)"],
    ["Reports", "No scans yet."],
    ["Compare runs", "Run two scans of this target to compare them."],
    ["Monitor", "Monitor these targets"],
    ["Bulk validation", "Targets file"],
    ["History", "No scans yet."],
    ["Catalogue", "Nmap Zero Day Scan"],
    ["Guides", "Scope and authorization"],
    ["Environment", "History keeps 50 runs and 20 reports per target."]
  ];
  const titles = await page.getByRole("main").locator("details[id^='websec-'] > summary span.font-medium").allTextContents();
  expect(titles).toEqual(rows.map(([title]) => title));
  for (const [title, content] of rows) {
    const row = page.getByRole("main").locator("details[id^='websec-']").filter({ has: page.getByText(title, { exact: true }) });
    await expect(row.getByText(content, { exact: true }).first()).toBeHidden();
    await openRow(page, title);
    await expect(row.getByText(content, { exact: true }).first()).toBeVisible();
  }
});

test("the workbench holds 390 px without horizontal overflow", async ({ page }) => {
  await mockStatus(page, status);
  await mockScan(page, reportWithModuleData);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/web-sec/");
  await page.getByRole("main").getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  await page.getByRole("main").locator("summary").filter({ hasText: /^Checks$/ }).click();
  await page.getByRole("main").getByRole("button", { name: "Domain information" }).click();
  await page.getByRole("main").getByRole("button", { name: "Security posture", exact: true }).click();
  for (const title of ["Scan options", "Catalogue", "Bulk validation"]) await openRow(page, title);
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("the monitor warns in a banner, links to compare, and saves its config", async ({ page }) => {
  await mockStatus(page, status);
  const warned: WebSecMonitorStatus = {
    ...monitorOff,
    config: { ...monitorOff.config, enabled: true, targets: ["example.test"] },
    targets: { "example.test": { lastRun: 1764000000, status: "ok", grade: "B", score: 84, lastReport: "20261124T000000Z-84.json" } },
    activeWarnings: [{ target: "example.test", level: "critical", since: 1764000000, flagged: ["content_scan|aws"],
      message: "1 new finding(s) at or above high; grade A → B. critical: AWS access key id appears in served content." }],
    events: [{ at: 1764000000, kind: "critical", target: "example.test", message: "1 new finding(s) at or above high" }]
  };
  await page.route("**/api/websec/monitor", (route) => route.fulfill({ json: warned }));
  const saved: WebSecMonitorConfig[] = [];
  await page.route("**/api/websec/monitor/config", (route) => {
    const body = route.request().postDataJSON() as { config: WebSecMonitorConfig };
    saved.push(body.config);
    return route.fulfill({ json: { ...warned, config: body.config } });
  });
  let ran = 0;
  await page.route("**/api/websec/monitor/run", (route) => {
    ran += 1;
    return route.fulfill({ status: 202, json: { queued: true } });
  });

  await page.goto("/web-sec/");
  const banner = page.getByRole("main").getByRole("alert").filter({ hasText: "The monitor found a serious regression" });
  await expect(banner).toBeVisible();
  await expect(banner.getByText("example.test")).toBeVisible();
  await banner.getByRole("button", { name: "Compare runs" }).click();
  await expect(page.getByRole("textbox", { name: "Target" })).toHaveValue("example.test");
  await expect(page.locator("#websec-compare")).toHaveAttribute("open", "");

  const row = page.locator("#websec-monitor");
  await expect(row.locator("summary")).toContainText("1");
  await openRow(page, "Monitor");
  await row.getByLabel("Monitored targets").fill("example.test\nbad host");
  await expect(row.getByText("Not a host name:")).toBeVisible();
  await expect(row.getByRole("button", { name: "Save monitor" })).toBeDisabled();
  await row.getByLabel("Monitored targets").fill("example.test\nsecond.test");
  await row.getByLabel("How often").selectOption("360");
  await row.getByLabel("Desktop notifications").uncheck();
  await row.getByRole("button", { name: "Save monitor" }).click();
  await expect(row.getByText("Saved on this computer")).toBeVisible();
  expect(saved[0]).toMatchObject({ enabled: true, targets: ["example.test", "second.test"], intervalMinutes: 360, notify: false });
  await row.getByRole("button", { name: "Check now" }).click();
  await expect(row.getByText("The check started; results appear here when it finishes.")).toBeVisible();
  expect(ran).toBe(1);
});

test("content, takeover and origin checks get dedicated panels", async ({ page }) => {
  await mockStatus(page, status);
  await mockScan(page, {
    ...report,
    modules: [
      { id: "content_scan", label: "Content and secret exposure", status: "ok", duration_ms: 50, findings: 2, error: "", note: "",
        data: { available: true, scripts_scanned: 2, bytes_scanned: 4096,
          secrets: [{ kind: "AWS access key id", severity: "critical", count: 1, samples: ["AKIA…MPLE"], where: ["app.js"] }],
          taint: [{ where: "search.js", variable: "term", sink: "innerHTML", line: 2, source_line: 1, code: "results.innerHTML = term" }],
          source_maps: [], exposed_source_maps: [], framework_data: { next_data: false } } },
      { id: "subdomain_takeover", label: "Subdomain takeover", status: "ok", duration_ms: 40, findings: 1, error: "", note: "",
        data: { candidates: 3, services: 12, confirmed: [], checked: [],
          dangling: [{ name: "old.example.test", service: "GitHub Pages", chain: ["old.example.test", "gone.github.io"], evidence: "gone.github.io does not resolve" }] } },
      { id: "origin_exposure", label: "Origin exposure", status: "ok", duration_ms: 30, findings: 1, error: "", note: "",
        data: { cdn: "Cloudflare", note: "a candidate origin, not proof",
          candidates: [{ name: "direct.example.test", addresses: ["203.0.113.7"], edge: "", status: 200 }],
          exposed: [{ name: "direct.example.test" }] } }
    ]
  });
  await page.goto("/web-sec/");
  await page.getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  await page.getByRole("main").locator("summary").filter({ hasText: /^Checks$/ }).click();

  await page.getByRole("main").getByRole("button", { name: "Content and secret exposure" }).click();
  const content = page.getByRole("region", { name: "Content and secret exposure details" });
  await expect(content.getByText("AKIA…MPLE")).toBeVisible();
  await expect(content.getByText("DOM-XSS candidates")).toBeVisible();
  await expect(content.getByText("results.innerHTML = term")).toBeVisible();

  await page.getByRole("main").getByRole("button", { name: "Subdomain takeover", exact: true }).click();
  const takeover = page.getByRole("region", { name: "Subdomain takeover details" });
  await expect(takeover.getByText("Dangling CNAMEs")).toBeVisible();
  await expect(takeover.getByText("old.example.test → gone.github.io")).toBeVisible();

  await page.getByRole("main").getByRole("button", { name: "Origin exposure", exact: true }).click();
  const origin = page.getByRole("region", { name: "Origin exposure details" });
  await expect(origin.getByText("Cloudflare")).toBeVisible();
  await expect(origin.getByRole("cell", { name: "yes" })).toBeVisible();
});

test("history marks favourites, deletes selected runs after confirming, and clears", async ({ page }) => {
  await mockStatus(page, status);
  const entries = [
    { target: "example.test", scanned_at: "2026-11-24T00:00:00+00:00", grade: "A", score: 95, summary: { total: 1 }, preset: "standard", active: false, refused: false, name: "20261124T000000Z-95.json", favourite: false },
    { target: "example.test", scanned_at: "2026-11-01T00:00:00+00:00", grade: "B", score: 80, summary: { total: 2 }, preset: "standard", active: false, refused: false, name: "20261101T000000Z-80.json", favourite: true }
  ];
  await page.route("**/api/websec/history*", (route) => route.fulfill({ json: { entries } }));
  await page.route("**/api/websec/runs/stats", (route) => route.fulfill({ json: {
    targets: 1, runs: 2, reports: 2, bytes: 4096, favourites: 1, grades: { A: 1 }, latestFindings: {}, latest: [] } }));
  const calls: { path: string; body: unknown }[] = [];
  await page.route(/\/api\/websec\/runs\/(favourite|delete|clear)$/, (route) => {
    calls.push({ path: new URL(route.request().url()).pathname, body: route.request().postDataJSON() });
    return route.fulfill({ status: 202, json: { deleted: 1, favourite: true } });
  });

  await page.goto("/web-sec/");
  await openRow(page, "History");
  const row = page.locator("#websec-history");
  await expect(row.getByText("4.0 KB")).toBeVisible();
  await row.getByLabel("Favourites only").check();
  await expect(row.getByText("2026-11-24T00:00:00+00:00")).toHaveCount(0);
  await row.getByLabel("Favourites only").uncheck();

  await row.getByRole("button", { name: "Favourite" }).first().click();
  await expect.poll(() => calls.length).toBe(1);
  expect(calls[0]).toEqual({ path: "/api/websec/runs/favourite", body: { target: "example.test", name: "20261124T000000Z-95.json", on: true } });

  await expect(row.getByRole("button", { name: "Delete selected" })).toBeDisabled();
  await row.getByLabel("Select 20261124T000000Z-95.json").check();
  await row.getByRole("button", { name: "Delete selected" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("20261124T000000Z-95.json")).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  expect(calls).toHaveLength(1); // cancelling deletes nothing
  await row.getByRole("button", { name: "Delete selected" }).click();
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();
  await expect.poll(() => calls.length).toBe(2);
  expect(calls[1]).toEqual({ path: "/api/websec/runs/delete", body: { target: "example.test", names: ["20261124T000000Z-95.json"] } });

  await row.getByRole("button", { name: "Clear all history" }).click();
  await dialog.getByRole("button", { name: "Delete", exact: true }).click();
  await expect.poll(() => calls.length).toBe(3);
  expect(calls[2]).toEqual({ path: "/api/websec/runs/clear", body: { all: true } });
});

test("the confirmation dialog shows the engine's plan and blocks a refused target", async ({ page }) => {
  await mockStatus(page, status);
  const sent = await mockScan(page);
  let refuse = false;
  await page.route("**/api/websec/plan", (route) => route.fulfill({ json: {
    target: "example.test", url: "https://example.test", preset: "standard", scheme: "https", active: true,
    scope: refuse ? { allowed: false, reason: "example.test is not in the scope", rule: "" } : { allowed: true, reason: "", rule: "example.test" },
    checks: [{ id: "tls_health", label: "TLS health", active: true, weight: "light", runs: !refuse, note: "" }],
    intrusive: refuse ? [] : ["tls_health"], available_intrusive: ["tls_health"], runs: refuse ? 0 : 16 } }));

  await page.goto("/web-sec/");
  await page.getByRole("textbox", { name: "Target" }).fill("example.test");
  await page.getByRole("main").getByLabel("Allow intrusive checks").check();
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("TLS health")).toBeVisible();          // from the engine, not the local table
  await expect(dialog.getByText("Port exposure")).toHaveCount(0);
  await expect(dialog.getByText("https://example.test")).toBeVisible();
  await page.keyboard.press("Escape");

  refuse = true;
  await page.getByRole("main").getByRole("button", { name: "Scan", exact: true }).click();
  await expect(dialog.getByText("example.test is not in the scope")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Run with intrusive checks" })).toBeDisabled();
  expect(sent).toHaveLength(0);
});
