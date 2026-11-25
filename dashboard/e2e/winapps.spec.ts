import { expect, test, type Page } from "@playwright/test";
import type { LabStatus } from "../src/lib/api";

const winapps = {
  available: true,
  reason: null,
  windows: [
    {
      windowId: 100,
      windowToken: "a".repeat(24),
      pid: 100,
      app: "Notepad",
      elevated: false,
      title: "Fixture - Notepad",
      className: "Notepad",
      x: 10,
      y: 20,
      width: 320,
      height: 240,
      dpi: 144
    }
  ]
};

// A real, decodable 1x1 PNG so the browser actually paints the mirror.
const PNG_1X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
  "base64"
);
const PNG_2X1 = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAYAAAD0In+KAAAADklEQVR4nGP4z8DwHwQBEPgD/U6VwW8AAAAASUVORK5CYII=",
  "base64"
);

function crc32(data: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Buffer): Buffer {
  const kind = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  kind.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([kind, data])), 8 + data.length);
  return chunk;
}

function largePng(): Buffer {
  const idatLength = PNG_1X1.readUInt32BE(33);
  const signatureAndHeader = PNG_1X1.subarray(0, 33);
  const idat = PNG_1X1.subarray(33, 33 + idatLength + 12);
  const end = PNG_1X1.subarray(33 + idatLength + 12);
  const text = Buffer.concat([Buffer.from("Comment\0"), Buffer.alloc(16 * 1024 * 1024, 97)]);
  return Buffer.concat([signatureAndHeader, idat, pngChunk("tEXt", text), end]);
}

function multipartFrame(png: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(`--frame\r\nContent-Type: image/png\r\nContent-Length: ${png.length}\r\n\r\n`),
    png,
    Buffer.from("\r\n")
  ]);
}

const labs: LabStatus[] = [
  { id: "winapps", label: "Windows Apps Lab", summary: "Local Windows app mirror with guarded UI Automation and input.", state: "ready", provider: "native-windows", reasons: [], requirements: [], notes: [], actions: [], installed: true },
  { id: "windows", label: "Windows Lab", summary: "Windows VM", state: "needs-setup", provider: "wsl2", reasons: [], requirements: [], notes: [], actions: [], installed: true },
  { id: "source", label: "Source Lab", summary: "Local source analysis", state: "ready", provider: "native-python", reasons: [], requirements: [], notes: [], actions: [], installed: true },
  { id: "macos", label: "macOS Lab", summary: "Native Xcode Simulator", state: "unavailable", provider: null, reasons: [], requirements: [], notes: [], actions: [], installed: true },
  { id: "ios", label: "iOS Lab", summary: "iOS Simulator", state: "unavailable", provider: null, reasons: [], requirements: [], notes: [], actions: [], installed: true },
  { id: "android", label: "Android Lab", summary: "Android analysis", state: "needs-setup", provider: "wsl2", reasons: [], requirements: [], notes: [], actions: [], installed: true },
  { id: "linux", label: "Linux Lab", summary: "Linux VM", state: "unavailable", provider: null, reasons: [], requirements: [], notes: [], actions: [], installed: true }
];

async function mockApi(page: Page, os: "windows" | "linux" = "windows") {
  const controlState = {
    armed: false,
    owner: null as string | null,
    expiresInSec: 0,
    audit: [] as unknown[],
    recentActions: [] as { time: number; kind: string; action?: string; app?: string; ok?: boolean }[]
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/host") body = {
      host: {
        os, osPretty: os === "windows" ? "Windows" : "Linux", arch: "x86_64", hostname: "test-host",
        cpus: 8, memory: 16 * 1024 ** 3, disk: { free: 100 * 1024 ** 3, total: 500 * 1024 ** 3 },
        kvm: { present: os === "linux", usable: os === "linux" },
        wsl: { guest: false, distributions: os === "windows" ? ["Ubuntu"] : [] },
        runtime: null, xcode: null, python: "3.12", root: "/tmp/os-lab", tools: [], providers: []
      },
      labs
    };
    else if (path === "/api/health") body = { status: "ok", version: "test", console: true };
    else if (path === "/api/jobs") body = { jobs: [] };
    else if (path === "/api/labs/winapps/apps") body = winapps;
    else if (path === "/api/labs/winapps/control") {
      if (route.request().method() === "POST") {
        const request = route.request().postDataJSON() as { armed: boolean; owner: string };
        Object.assign(controlState, request.armed
          ? { armed: true, owner: request.owner, expiresInSec: 600 }
          : { armed: false, owner: null, expiresInSec: 0 });
        const auditEntry = {
          time: Date.now() / 1000, kind: request.armed ? "arm" : "disarm", ok: true
        };
        controlState.audit.push(auditEntry);
        controlState.recentActions.push(auditEntry);
      }
      body = controlState;
    }
    else if (path === "/api/labs/winapps/apps/100/elements") body = {
      windowId: 100, windowToken: "a".repeat(24), app: "Notepad", bounds: { x: 10, y: 20, width: 320, height: 240 },
      revision: "1".repeat(16), engine: "uia", trimmed: false,
      elements: [{ elementId: "c".repeat(16), role: "Button", label: "Save", x: 40, y: 20, w: 80, h: 24, enabled: true, focused: true }],
      diff: { added: [], changed: [], removed: [] }
    };
    else if (path === "/api/labs/winapps/apps/100/search") body = {
      windowId: 100, windowToken: "a".repeat(24), app: "Notepad", revision: "1".repeat(16), engine: "uia", query: "save", count: 1,
      hits: [{ elementId: "c".repeat(16), role: "Button", label: "Save", x: 40, y: 20, w: 80, h: 24, enabled: true, focused: true }]
    };
    else if (path === "/api/labs/winapps/click") body = { ok: true, actionSent: true, windowId: 100, x: 80, y: 32 };
    else if (path === "/api/labs/winapps/input") body = { ok: true, actionSent: true, windowId: 100, kind: "type", textLength: 5 };
    else if (path === "/api/labs/winapps/stop") {
      Object.assign(controlState, { armed: false, owner: null, expiresInSec: 0 });
      const panicEntry = { time: Date.now() / 1000, kind: "panic-stop", ok: true };
      controlState.audit.push(panicEntry);
      controlState.recentActions.push(panicEntry);
      body = { ok: true, disarmed: true };
    }
    else if (path === "/api/labs/winapps/config") body = { lab: "winapps", path: "config.env", exists: true, fields: [], profiles: [], backups: [], endpoints: [] };
    else if (path === "/api/labs/winapps/monitor") body = { lab: "winapps", state: "stopped", containers: [] };
    await route.fulfill({ json: body });
  });
  return controlState;
}

test("the Windows Apps Lab mirrors a real window and exposes UI Automation controls", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200,
    contentType: "image/png",
    body: PNG_1X1
  }));
  const streamBody = Buffer.concat([
    Buffer.from(`--frame\r\nContent-Type: image/png\r\nContent-Length: ${PNG_1X1.length}\r\n\r\n`),
    PNG_1X1,
    Buffer.from("\r\n")
  ]);
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: streamBody
  }));

  await page.goto("/labs/winapps/");
  await expect(page.getByText("App mirror")).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Window" })).toContainText("Notepad");
  await expect(page.getByText("320×240")).toBeVisible();
  const mirror = page.locator("img[alt='Mirror of Notepad']");
  // Painted at the window's own 4:3 shape, not collapsed to an empty box.
  await expect(mirror).toBeVisible();
  const box = await mirror.boundingBox();
  expect(box!.height).toBeGreaterThan(100);
  expect(box!.width / box!.height).toBeCloseTo(320 / 240, 1);
  await expect(page.getByText("Elevated")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Arm control" })).toBeVisible();
});

test("UIA hotspots and keyboard input require preview, arm and explicit confirmation", async ({ page }) => {
  const actions: { path: string; body: Record<string, unknown> }[] = [];
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200, contentType: "image/png", body: PNG_1X1
  }));
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: Buffer.concat([
      Buffer.from(`--frame\r\nContent-Type: image/png\r\nContent-Length: ${PNG_1X1.length}\r\n\r\n`),
      PNG_1X1,
      Buffer.from("\r\n")
    ])
  }));
  await page.route("**/api/labs/winapps/click", async (route) => {
    actions.push({ path: "click", body: route.request().postDataJSON() as Record<string, unknown> });
    await route.fulfill({
      json: { ok: true, actionSent: true, windowId: 100, x: 80, y: 32, action: "click", actionId: "click-a" }
    });
  });
  await page.route("**/api/labs/winapps/input", async (route) => {
    actions.push({ path: "input", body: route.request().postDataJSON() as Record<string, unknown> });
    await route.fulfill({ json: { ok: true, actionSent: true, windowId: 100, kind: "type", textLength: 5 } });
  });

  await page.goto("/labs/winapps/");
  await page.getByRole("button", { name: "Elements" }).click();
  await page.getByRole("textbox", { name: "Search elements" }).fill("save");
  await page.getByRole("button", { name: "Search", exact: true }).click();
  await expect(page.getByText("1 matches")).toBeVisible();
  const hotspot = page.getByRole("button", { name: "Button: Save" });
  await expect(hotspot).toBeVisible();
  await hotspot.click();
  await expect(page.getByRole("dialog")).toContainText("Click UI element");
  await expect(page.getByRole("button", { name: "Confirm and send" })).toBeDisabled();
  await expect(page.getByText("Arm control before confirming this action.")).toBeVisible();
  await page.getByRole("button", { name: "Cancel" }).click();

  await page.getByRole("button", { name: "Arm control" }).click();
  await expect(page.getByRole("button", { name: "Disarm control" })).toBeVisible();
  await hotspot.click();
  await page.getByRole("button", { name: "Confirm and send" }).click();
  await expect.poll(() => actions.length).toBe(1);
  expect(actions[0]).toMatchObject({
    path: "click",
    body: {
      confirm: true, owner: expect.any(String), windowId: 100,
      windowToken: "a".repeat(24), revision: "1".repeat(16),
      elementId: "c".repeat(16), elementBounds: { x: 40, y: 20, w: 80, h: 24 },
      x: 80, y: 32, action: "click", actionId: expect.any(String)
    }
  });

  await page.getByRole("textbox", { name: "Text to type" }).fill("hello");
  await page.getByRole("button", { name: "Preview text" }).click();
  await expect(page.getByRole("dialog")).toContainText("hello");
  await expect.poll(() => actions.length).toBe(1);
  await page.getByRole("button", { name: "Confirm and send" }).click();
  await expect.poll(() => actions.length).toBe(2);
  expect(actions[1]).toMatchObject({
    path: "input",
    body: {
      confirm: true, owner: expect.any(String), kind: "type", text: "hello",
      windowId: 100, windowToken: "a".repeat(24), revision: "1".repeat(16),
      elementId: "c".repeat(16), elementBounds: { x: 40, y: 20, w: 80, h: 24 },
      actionId: expect.any(String)
    }
  });
});

test("the mirror parses a stream frame and displays it instead of only the snapshot", async ({ page }) => {
  await mockApi(page);
  let snapshots = 0;
  let streams = 0;
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => {
    snapshots++;
    return route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 });
  });
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => {
    streams++;
    return route.fulfill({
      status: 200,
      contentType: "multipart/x-mixed-replace; boundary=frame",
      body: multipartFrame(PNG_2X1)
    });
  });

  const streamRequest = page.waitForRequest((request) => request.url().includes("/apps/100/stream?fps="));
  await page.goto("/labs/winapps/");
  await streamRequest;
  const mirror = page.locator("img[alt='Mirror of Notepad']");
  await expect.poll(() => mirror.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBe(2);
  expect(streams).toBeGreaterThan(0);
  expect(snapshots).toBe(1);
});

test("the stream accepts valid PNG frames larger than 16 MB", async ({ page }) => {
  await mockApi(page);
  const oversizedFrame = largePng();
  expect(oversizedFrame.length).toBeGreaterThan(16 * 1024 * 1024);
  await page.addInitScript(() => {
    const state = window as Window & { __winappsPngSizes?: number[] };
    state.__winappsPngSizes = [];
    const createObjectURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (object) => {
      if (object instanceof Blob && object.type === "image/png") state.__winappsPngSizes?.push(object.size);
      return createObjectURL(object);
    };
  });
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200, contentType: "image/png", body: PNG_1X1
  }));
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: multipartFrame(oversizedFrame)
  }));

  await page.goto("/labs/winapps/");
  await expect.poll(() => page.evaluate(() =>
    (window as Window & { __winappsPngSizes?: number[] }).__winappsPngSizes?.some((size) => size > 16 * 1024 * 1024)
  ), { timeout: 20_000 }).toBe(true);
});

test("invalid stream frames are rejected and snapshots continue as fallback", async ({ page }) => {
  await mockApi(page);
  let snapshots = 0;
  let releaseInitialSnapshot!: () => void;
  const initialSnapshotGate = new Promise<void>((resolve) => { releaseInitialSnapshot = resolve; });
  await page.route("**/api/labs/winapps/apps/100/screenshot*", async (route) => {
    snapshots++;
    if (snapshots === 1) await initialSnapshotGate;
    return route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 });
  });
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: multipartFrame(Buffer.alloc(64))
  }));

  await page.goto("/labs/winapps/");
  await expect(page.getByRole("alert").filter({
    hasText: "The mirror stream returned an invalid PNG frame"
  })).toBeVisible();
  releaseInitialSnapshot();
  await expect.poll(() => snapshots).toBeGreaterThan(1);
});

test("a stalled stream switches to screenshot polling", async ({ page }) => {
  test.setTimeout(30_000);
  await mockApi(page);
  let snapshots = 0;
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => {
    snapshots++;
    return route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 });
  });
  await page.addInitScript(() => {
    const originalFetch = window.fetch.bind(window);
    window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const requestUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (!new URL(requestUrl, window.location.href).pathname.endsWith("/stream")) {
        return originalFetch(input, init);
      }
      const body = new ReadableStream<Uint8Array>({
        pull() { return new Promise<void>(() => {}); }
      });
      return Promise.resolve(new Response(body, {
        status: 200,
        headers: { "Content-Type": "multipart/x-mixed-replace; boundary=frame" }
      }));
    }) as typeof window.fetch;
  });

  await page.goto("/labs/winapps/");
  await expect.poll(() => snapshots, { timeout: 25_000 }).toBeGreaterThan(1);
});

test("a stale stream cannot replace the selected window's newer frame", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps", (route) => route.fulfill({
    json: {
      ...winapps,
      windows: [
        winapps.windows[0],
        {
          ...winapps.windows[0], windowId: 200, windowToken: "b".repeat(24),
          pid: 200, app: "Calculator", title: "Calculator"
        }
      ]
    }
  }));
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200, contentType: "image/png", body: PNG_1X1
  }));
  await page.route("**/api/labs/winapps/apps/200/screenshot*", (route) => route.fulfill({
    status: 200, contentType: "image/png", body: PNG_2X1
  }));
  await page.addInitScript(() => {
    const state = window as Window & {
      __winappsStreams?: Map<number, ReadableStreamDefaultController<Uint8Array>>;
    };
    state.__winappsStreams = new Map();
    const originalFetch = window.fetch.bind(window);
    window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const requestUrl = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      const match = new URL(requestUrl, window.location.href).pathname.match(/\/apps\/(\d+)\/stream$/);
      if (!match) return originalFetch(input, init);
      const body = new ReadableStream<Uint8Array>({
        start(controller) { state.__winappsStreams?.set(Number(match[1]), controller); }
      });
      return Promise.resolve(new Response(body, {
        status: 200,
        headers: { "Content-Type": "multipart/x-mixed-replace; boundary=frame" }
      }));
    }) as typeof window.fetch;
  });

  await page.goto("/labs/winapps/");
  const mirror = page.locator("img[alt='Mirror of Notepad']");
  await expect.poll(() => mirror.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBe(1);
  await expect.poll(() => page.evaluate(() =>
    (window as Window & { __winappsStreams?: Map<number, unknown> }).__winappsStreams?.has(100)
  )).toBe(true);
  await page.getByRole("combobox", { name: "Window" }).selectOption("200");
  const calculator = page.locator("img[alt='Mirror of Calculator']");
  await expect.poll(() => calculator.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBe(2);
  await expect.poll(() => page.evaluate(() =>
    (window as Window & { __winappsStreams?: Map<number, unknown> }).__winappsStreams?.has(200)
  )).toBe(true);
  const selectedSrc = await calculator.getAttribute("src");
  const staleFrame = multipartFrame(PNG_1X1).toString("base64");
  await page.evaluate((encoded) => {
    const bytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
    (window as Window & {
      __winappsStreams?: Map<number, ReadableStreamDefaultController<Uint8Array>>;
    }).__winappsStreams?.get(100)?.enqueue(bytes);
  }, staleFrame);
  await expect(calculator).toHaveAttribute("src", selectedSrc!);
  await expect.poll(() => calculator.evaluate((image: HTMLImageElement) => image.naturalWidth)).toBe(2);
});

test("the floating mirror stays within a narrow viewport while resized and dragged", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 720 });
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200, contentType: "image/png", body: PNG_1X1
  }));
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: multipartFrame(PNG_1X1)
  }));

  await page.goto("/labs/winapps/");
  const panel = page.locator(".iux-card.fixed");
  await expect(panel).toBeVisible();
  await expect(panel.getByRole("button", { name: "Refresh" })).toBeVisible();
  const dockButton = panel.getByRole("button", { name: "Dock the panel" });
  const hideButton = panel.getByRole("button", { name: "Hide the app mirror" });
  await expect(dockButton).toBeVisible();
  await expect(hideButton).toBeVisible();
  const resizeHandle = panel.locator(".cursor-nwse-resize");
  const handle = await resizeHandle.boundingBox();
  await page.mouse.move(handle!.x + 4, handle!.y + 4);
  await page.mouse.down();
  await page.mouse.move(handle!.x + 500, handle!.y + 500);
  await page.mouse.up();
  const dragHandle = await panel.locator(":scope > div").first().boundingBox();
  await page.mouse.move(dragHandle!.x + 50, dragHandle!.y + 10);
  await page.mouse.down();
  await page.mouse.move(900, 900);
  await page.mouse.up();
  const bounds = await panel.boundingBox();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.y).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(375);
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(720);
  for (const control of [dockButton, hideButton]) {
    const controlBounds = await control.boundingBox();
    expect(controlBounds!.x).toBeGreaterThanOrEqual(bounds!.x);
    expect(controlBounds!.x + controlBounds!.width).toBeLessThanOrEqual(bounds!.x + bounds!.width);
  }
});

test("double-click and scroll use confirmed input actions and refresh UIA plus audit state", async ({ page }) => {
  const controlState = await mockApi(page);
  const actions: Record<string, unknown>[] = [];
  let elementsReads = 0;
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname === "/api/labs/winapps/apps/100/elements") elementsReads++;
  });
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200, contentType: "image/png", body: PNG_1X1
  }));
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: Buffer.concat([
      Buffer.from(`--frame\r\nContent-Type: image/png\r\nContent-Length: ${PNG_1X1.length}\r\n\r\n`),
      PNG_1X1,
      Buffer.from("\r\n")
    ])
  }));
  await page.route("**/api/labs/winapps/click", async (route) => {
    const body = route.request().postDataJSON() as Record<string, unknown>;
    actions.push(body);
    controlState.recentActions.push({
      time: Date.now() / 1000, kind: "click", action: String(body.action ?? "click"), app: "Notepad", ok: true
    });
    await route.fulfill({ json: { ok: true, actionSent: true, ...body } });
  });

  await page.goto("/labs/winapps/");
  await page.getByRole("button", { name: "Elements" }).click();
  await expect(page.getByRole("button", { name: "Button: Save" })).toBeVisible();
  await page.getByRole("button", { name: "Arm control" }).click();
  await expect(page.getByRole("button", { name: "Disarm control" })).toBeVisible();
  await page.getByRole("combobox", { name: "Mouse action" }).selectOption("double_click");
  await page.getByRole("button", { name: "Button: Save" }).click();
  await expect(page.getByRole("dialog")).toContainText("Double-click UI element");
  const firstElementsRead = elementsReads;
  await page.getByRole("button", { name: "Confirm and send" }).click();
  await expect.poll(() => actions.length).toBe(1);
  expect(actions[0]).toMatchObject({
    action: "double_click", x: 80, y: 32, confirm: true, owner: expect.any(String), windowId: 100,
    windowToken: "a".repeat(24), revision: "1".repeat(16), elementId: "c".repeat(16), actionId: expect.any(String)
  });
  await expect.poll(() => elementsReads).toBeGreaterThan(firstElementsRead);
  await expect(page.getByText("Double-click · Notepad")).toBeVisible();

  await page.getByRole("combobox", { name: "Mouse action" }).selectOption("scroll");
  await page.getByRole("button", { name: "Button: Save" }).click();
  await expect(page.getByRole("dialog")).toContainText("Scroll UI element");
  await expect(page.getByRole("dialog")).toContainText("Scroll delta: 120");
  await page.getByRole("button", { name: "Confirm and send" }).click();
  await expect.poll(() => actions.length).toBe(2);
  expect(actions[1]).toMatchObject({
    action: "scroll", deltaX: 0, deltaY: 120, confirm: true,
    windowToken: "a".repeat(24), revision: "1".repeat(16), elementId: "c".repeat(16), actionId: expect.any(String)
  });
  await expect(page.getByText("Scroll · Notepad")).toBeVisible();
});

test("the mirror can be dragged, resized, docked, hidden and reopened", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 200,
    contentType: "image/png",
    body: PNG_1X1
  }));
  await page.route("**/api/labs/winapps/apps/100/stream?fps=*", (route) => route.fulfill({
    status: 200,
    contentType: "multipart/x-mixed-replace; boundary=frame",
    body: Buffer.concat([
      Buffer.from(`--frame\r\nContent-Type: image/png\r\nContent-Length: ${PNG_1X1.length}\r\n\r\n`),
      PNG_1X1,
      Buffer.from("\r\n")
    ])
  }));

  await page.goto("/labs/winapps/");
  const panel = page.locator(".iux-card.fixed");
  await expect(panel).toBeVisible();
  const beforeDrag = await panel.boundingBox();
  const header = panel.locator(":scope > div").first();
  const headerBox = await header.boundingBox();
  await page.mouse.move(headerBox!.x + 100, headerBox!.y + 10);
  await page.mouse.down();
  await page.mouse.move(headerBox!.x + 60, headerBox!.y - 10);
  await page.mouse.up();
  const afterDrag = await panel.boundingBox();
  expect(afterDrag!.x).toBeLessThan(beforeDrag!.x - 30);
  expect(afterDrag!.y).toBeLessThan(beforeDrag!.y - 15);

  const beforeResize = await panel.boundingBox();
  const resizeHandle = panel.locator(".cursor-nwse-resize");
  const handleBox = await resizeHandle.boundingBox();
  await page.mouse.move(handleBox!.x + 4, handleBox!.y + 4);
  await page.mouse.down();
  await page.mouse.move(handleBox!.x + 44, handleBox!.y + 34);
  await page.mouse.up();
  const afterResize = await panel.boundingBox();
  expect(afterResize!.width).toBeGreaterThan(beforeResize!.width + 20);
  expect(afterResize!.height).toBeGreaterThan(beforeResize!.height + 15);

  await page.getByRole("button", { name: "Dock the panel" }).click();
  await expect(page.getByRole("button", { name: "Float the panel" })).toBeVisible();
  await page.getByRole("button", { name: "Hide the app mirror" }).click();
  await page.getByRole("button", { name: "Show the app mirror" }).click();
  await expect(page.getByText("App mirror")).toBeVisible();
});

test("an elevated window is marked instead of silently failing", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps", (route) => route.fulfill({
    json: { ...winapps, windows: [{ ...winapps.windows[0], elevated: true }] }
  }));
  await page.route("**/api/labs/winapps/apps/100/screenshot*", (route) => route.fulfill({
    status: 400,
    json: { error: "Could not capture that window; try another application window" }
  }));

  await page.goto("/labs/winapps/");
  await expect(page.getByText("Elevated")).toBeVisible();
  await expect(page.getByText("Could not capture that window; try another application window").first()).toBeVisible();
});

test("the panel reports an unavailable native mirror", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps", (route) => route.fulfill({
    json: { available: false, reason: "Native Windows app mirror needs a Windows host", windows: [] }
  }));
  await page.goto("/labs/winapps/");
  await expect(page.getByText("Native Windows app mirror needs a Windows host")).toBeVisible();
});

test("non-Windows hosts never query the Windows app mirror", async ({ page }) => {
  const requests: string[] = [];
  await mockApi(page, "linux");
  await page.route("**/api/labs/winapps/apps", (route) => {
    requests.push(new URL(route.request().url()).pathname);
    return route.fulfill({ json: { available: false, reason: "Windows only", windows: [] } });
  });

  await page.goto("/labs/winapps/");
  await expect(page.getByRole("heading", { name: "Window mirror" })).toHaveCount(0);
  expect(requests).toEqual([]);
});

test("a restricted window is listed but disabled and never captured", async ({ page }) => {
  await mockApi(page);
  const captured: string[] = [];
  await page.route("**/api/labs/winapps/apps", (route) => route.fulfill({
    json: {
      ...winapps,
      windows: [
        { ...winapps.windows[0], windowId: 200, app: "1Password", title: "(restricted)", restricted: true, reason: "password-manager" },
        { ...winapps.windows[0], restricted: false, reason: null }
      ]
    }
  }));
  await page.route("**/api/labs/winapps/apps/*/screenshot", (route) => {
    captured.push(new URL(route.request().url()).pathname);
    return route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 });
  });

  await page.goto("/labs/winapps/");
  await expect(page.locator("select#winapps-window option", { hasText: "1Password" })).toBeDisabled();
  await expect(page.getByText("Some windows are restricted and cannot be mirrored.")).toBeVisible();
  await expect(page.locator("img[alt='Mirror of Notepad']")).toBeVisible();
  expect(captured.length).toBeGreaterThan(0);
  expect(captured.every((path) => path.includes("/100/"))).toBe(true);
});

test("when every window is restricted the panel explains it instead of spinning", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/labs/winapps/apps", (route) => route.fulfill({
    json: {
      ...winapps,
      windows: [{ ...winapps.windows[0], windowId: 200, app: "1Password", title: "(restricted)", restricted: true, reason: "password-manager" }]
    }
  }));
  await page.goto("/labs/winapps/");
  await expect(page.getByText("Some windows are restricted and cannot be mirrored.")).toBeVisible();
  await expect(page.locator("[aria-busy='true']")).toHaveCount(0);
  await expect(page.locator("img[alt^='Mirror of']")).toHaveCount(0);
});

test("a window that turns restricted stops being shown and captured", async ({ page }) => {
  await mockApi(page);
  let inventoryCalls = 0;
  const captured: string[] = [];
  await page.route("**/api/labs/winapps/apps", (route) => {
    inventoryCalls += 1;
    const restricted = inventoryCalls > 1;
    return route.fulfill({
      json: { ...winapps, windows: [{ ...winapps.windows[0], restricted, reason: restricted ? "private-window" : null, title: restricted ? "(restricted)" : "Fixture - Notepad" }] }
    });
  });
  await page.route("**/api/labs/winapps/apps/100/screenshot", (route) => {
    captured.push("hit");
    return route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 });
  });
  await page.goto("/labs/winapps/");
  await expect(page.locator("img[alt='Mirror of Notepad']")).toBeVisible();
  await expect(page.locator("img[alt^='Mirror of']")).toHaveCount(0, { timeout: 10000 });
  const settled = captured.length;
  await page.waitForTimeout(4000);
  expect(captured.length).toBe(settled);
});

test("switching away from a restricted window clears its image before the next capture arrives", async ({ page }) => {
  await mockApi(page);
  let inventoryCalls = 0;
  await page.route("**/api/labs/winapps/apps", (route) => {
    inventoryCalls += 1;
    const flipped = inventoryCalls > 1;
    return route.fulfill({
      json: {
        ...winapps,
        windows: [
          { ...winapps.windows[0], restricted: flipped, reason: flipped ? "private-window" : null, title: flipped ? "(restricted)" : "Fixture - Notepad" },
          { ...winapps.windows[0], windowId: 101, app: "Calc", title: "Calculator" }
        ]
      }
    });
  });
  await page.route("**/api/labs/winapps/apps/100/screenshot", (route) =>
    route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 }));
  await page.route("**/api/labs/winapps/apps/101/screenshot", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 6000));
    await route.fulfill({ status: 200, contentType: "image/png", body: PNG_1X1 }).catch(() => undefined);
  });
  await page.goto("/labs/winapps/");
  await expect(page.locator("img[alt='Mirror of Notepad']")).toBeVisible();
  await expect(page.locator("img[alt^='Mirror of']")).toHaveCount(0, { timeout: 10000 });
  await expect(page.locator("img[alt='Mirror of Calc']")).toBeVisible({ timeout: 15000 });
});
