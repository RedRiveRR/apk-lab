import { expect, test, type Page } from "@playwright/test";
import type { WebSecJob, WebSecModule, WebSecReport, WebSecStatus } from "../src/lib/api";

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

const job = (state: WebSecJob["state"], extra: Partial<WebSecJob> = {}): WebSecJob => ({
  id: "scan-1", state, target: "example.test", preset: "standard", active: true, started: 1, ...extra
});

async function mockStatus(page: Page, value: WebSecStatus) {
  await page.route("**/api/websec/status", (route) => route.fulfill({ json: value }));
  await page.route("**/api/websec/modules", (route) => route.fulfill({ json: { modules } }));
  await page.route("**/api/websec/history*", (route) => route.fulfill({ json: { entries: [] } }));
  await page.route("**/api/websec/reports*", (route) => route.fulfill({ json: { reports: [] } }));
}

test("a ready lab scans a target and shows the graded report", async ({ page }) => {
  await mockStatus(page, status);
  const sent: Record<string, unknown>[] = [];
  let polls = 0;
  await page.route(/\/api\/websec\/scans$/, async (route) => {
    sent.push(route.request().postDataJSON());
    return route.fulfill({ status: 202, json: job("running") });
  });
  await page.route(/\/api\/websec\/scans\/scan-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? job("running") : job("done", { report }) });
  });
  await page.route("**/api/websec/history*", (route) => route.fulfill({
    json: { entries: [{ target: "example.test", scanned_at: "2026-11-24T00:00:00+00:00", grade: "A", score: 95, summary: { total: 1 } }] }
  }));

  await page.goto("/web-sec/");
  await expect(page.getByRole("main").getByRole("heading", { name: "Web Sec Lab" })).toBeVisible();
  await page.getByRole("main").getByLabel("Target").fill("example.test");
  await page.getByRole("main").getByLabel("Allow intrusive checks").check();
  await page.getByRole("main").getByRole("button", { name: "Scan" }).click();
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
  await expect(page.getByRole("main").getByRole("button", { name: "Scan" })).toBeDisabled();
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
  await page.getByRole("main").getByLabel("Target").fill("example.test");
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
  let polls = 0;
  await page.route(/\/api\/websec\/scans$/, (route) => route.fulfill({ status: 202, json: job("running") }));
  await page.route(/\/api\/websec\/scans\/scan-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? job("running") : job("done", { report: reportWithModuleData }) });
  });

  await page.goto("/web-sec/");
  await page.getByRole("main").getByLabel("Target").fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan" }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();

  const whoisToggle = page.getByRole("main").getByRole("button", { name: "Domain information" });
  await expect(whoisToggle).toHaveAttribute("aria-expanded", "false");
  await whoisToggle.click();
  await expect(whoisToggle).toHaveAttribute("aria-expanded", "true");
  const whoisRegion = page.getByRole("region", { name: "Domain information details" });
  await expect(whoisRegion).toBeVisible();
  await expect(whoisRegion.getByText("TEST Registrar")).toBeVisible();
  await expect(whoisRegion.getByText("ns1.example.test")).toBeVisible();

  const headersToggle = page.getByRole("main").getByRole("button", { name: "Security posture" });
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
    return route.fulfill({ json: { content: `content-${format}`, format, name: "20261124T000000Z-95.json" } });
  });

  await page.goto("/web-sec/");
  await page.getByRole("main").getByLabel("Target").fill("example.test");
  await expect(page.getByRole("main").getByText("20261124T000000Z-95.json")).toBeVisible();

  for (const [button, extension] of [
    ["JSON", "json"],
    ["SARIF", "sarif"],
    ["HTML", "html"],
    ["Markdown", "md"]
  ] as const) {
    const pending = page.waitForEvent("download");
    await page.getByRole("main").getByRole("button", { name: button }).click();
    const download = await pending;
    expect(download.suggestedFilename()).toBe(`example.test.20261124T000000Z-95.${extension}`);
  }
  expect(formats).toEqual(["json", "sarif", "html", "markdown"]);

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
  const sent: Record<string, unknown>[] = [];
  let polls = 0;
  await page.route(/\/api\/websec\/scans$/, async (route) => {
    sent.push(route.request().postDataJSON());
    return route.fulfill({ status: 202, json: job("running") });
  });
  await page.route(/\/api\/websec\/scans\/scan-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? job("running") : job("done", { report }) });
  });

  await page.goto("/web-sec/");
  await page.getByRole("main").getByLabel("Target").fill("example.test");
  await page.getByRole("main").getByLabel("Request timeout (s)").fill("12");
  await page.getByRole("main").getByLabel("Scan budget (s)").fill("120");
  await page.getByRole("main").getByRole("button", { name: "Scan" }).click();
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
  await expect(page.getByRole("main").getByText("2026-11-24T00:00:00+00:00")).toBeVisible();
  await page.getByRole("main").getByRole("button", { name: "Open" }).click();
  await expect(page.getByRole("main").getByText("running")).toBeVisible();
  await expect(page.getByRole("main").getByText("ok").first()).toBeVisible();
  await expect(page.getByRole("main").getByText("pending")).toBeVisible();
  await expect(page.getByRole("main").getByText("Content-Security-Policy is missing")).toBeVisible();
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
  await page.getByRole("main").getByLabel("Target").fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan" }).click();
  await expect(page.getByRole("main").getByText("DNS records")).toBeVisible();
  await expect(page.getByRole("main").getByText("running")).toBeVisible();
  await expect(page.getByRole("main").getByText("security_analysis")).toBeVisible();
  await expect(page.getByRole("main").getByText("Content-Security-Policy is missing")).toBeVisible();
});

test("the workbench holds 390 px without horizontal overflow", async ({ page }) => {
  await mockStatus(page, status);
  let polls = 0;
  await page.route(/\/api\/websec\/scans$/, (route) => route.fulfill({ status: 202, json: job("running") }));
  await page.route(/\/api\/websec\/scans\/scan-1$/, (route) => {
    polls += 1;
    return route.fulfill({ json: polls < 2 ? job("running") : job("done", { report: reportWithModuleData }) });
  });

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/web-sec/");
  await page.getByRole("main").getByLabel("Target").fill("example.test");
  await page.getByRole("main").getByRole("button", { name: "Scan" }).click();
  await expect(page.getByRole("main").getByText("95/100")).toBeVisible();
  await page.getByRole("main").getByRole("button", { name: "Domain information" }).click();
  await page.getByRole("main").getByRole("button", { name: "Security posture" }).click();
  const overflow = await page.evaluate(() =>
    document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
