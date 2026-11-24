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
