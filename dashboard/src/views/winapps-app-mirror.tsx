/**
 * Windows Apps Lab mirror: a draggable, resizable view of one real desktop window.
 * The mirror keeps capture, UI Automation and guarded input tied to one window; input is opt-in, previewed, confirmed, and guarded by the backend arm lock.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowClockwiseIcon, CircleNotchIcon, CrosshairIcon, EyeIcon, HandIcon, PushPinIcon, XIcon
} from "@phosphor-icons/react";
import { Badge, Empty, Field, Modal, Skeleton, Status } from "../components/ui";
import {
  api, message, usePoll, type WinActionBinding, type WinApp, type WinAppsInfo, type WinAuditRow,
  type WinControlState, type WinElement, type WinElementsInfo, type WinInputKey
} from "../lib/api";

const MIRROR_INTERVAL = 1500;
const INVENTORY_INTERVAL = 5000;
const ELEMENTS_INTERVAL = 5000;
const MIN_WIDTH = 280;
const MIN_HEIGHT = 240;
const FPS_HOVER = 5;
const FPS_IDLE = 1.2;
const INPUT_KEYS: WinInputKey[] = ["tab", "escape", "backspace", "delete", "up", "down", "left", "right", "enter"];
const STREAM_IDLE_TIMEOUT_MS = 10_000;
const STREAM_CONNECT_TIMEOUT_MS = 10_000;
const MAX_CAPTURE_PIXELS = 7680 * 4320;
const MAX_STREAM_FRAME_BYTES = MAX_CAPTURE_PIXELS * 4 + 1024 * 1024;
const MAX_STREAM_HEADER_BYTES = 16_384;
const MAX_SCROLL_DELTA = 1200;

const MOUSE_ACTIONS = ["click", "double_click", "right_click", "scroll"] as const;
type MouseAction = typeof MOUSE_ACTIONS[number];
const MOUSE_ACTION_LABELS: Record<MouseAction, string> = {
  click: "Click",
  double_click: "Double-click",
  right_click: "Right-click",
  scroll: "Scroll"
};

const clamp = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max);

type Rect = { left: number; top: number; right: number; bottom: number };

function overlaps(a: Rect, b: Rect): boolean {
  return a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
}

function hotspotStyles(
  element: WinElement,
  elements: WinElement[],
  bounds: { width: number; height: number },
  display: { width: number; height: number },
  coarsePointer: boolean
) {
  const displayWidth = display.width || bounds.width;
  const displayHeight = display.height || bounds.height;
  const scaleX = displayWidth / bounds.width;
  const scaleY = displayHeight / bounds.height;
  const exact: Rect = {
    left: element.x * scaleX,
    top: element.y * scaleY,
    right: (element.x + element.w) * scaleX,
    bottom: (element.y + element.h) * scaleY
  };
  let hit = { ...exact };
  if (coarsePointer) {
    const neighbors = elements.filter((candidate) => candidate.elementId !== element.elementId).map((candidate) => ({
      left: candidate.x * scaleX,
      top: candidate.y * scaleY,
      right: (candidate.x + candidate.w) * scaleX,
      bottom: (candidate.y + candidate.h) * scaleY
    }));
    if (!neighbors.some((neighbor) => overlaps(exact, neighbor))) {
      const centerX = (exact.left + exact.right) / 2;
      const centerY = (exact.top + exact.bottom) / 2;
      hit = {
        left: Math.max(0, centerX - Math.max(44, exact.right - exact.left) / 2),
        top: Math.max(0, centerY - Math.max(44, exact.bottom - exact.top) / 2),
        right: Math.min(displayWidth, centerX + Math.max(44, exact.right - exact.left) / 2),
        bottom: Math.min(displayHeight, centerY + Math.max(44, exact.bottom - exact.top) / 2)
      };
      for (const neighbor of neighbors) {
        if (!overlaps(hit, neighbor)) continue;
        const horizontalGap = exact.right <= neighbor.left || neighbor.right <= exact.left;
        const verticalGap = exact.bottom <= neighbor.top || neighbor.bottom <= exact.top;
        const verticalOverlap = exact.top < neighbor.bottom && neighbor.top < exact.bottom;
        const horizontalOverlap = exact.left < neighbor.right && neighbor.left < exact.right;
        if (horizontalGap && verticalOverlap) {
          if (neighbor.left >= exact.right) hit.right = Math.min(hit.right, neighbor.left);
          else hit.left = Math.max(hit.left, neighbor.right);
        } else if (verticalGap && horizontalOverlap) {
          if (neighbor.top >= exact.bottom) hit.bottom = Math.min(hit.bottom, neighbor.top);
          else hit.top = Math.max(hit.top, neighbor.bottom);
        } else {
          hit = { ...exact };
          break;
        }
      }
      if (neighbors.some((neighbor) => overlaps(hit, neighbor))) hit = { ...exact };
      hit.left = Math.min(hit.left, exact.left);
      hit.top = Math.min(hit.top, exact.top);
      hit.right = Math.max(hit.right, exact.right);
      hit.bottom = Math.max(hit.bottom, exact.bottom);
    }
  }
  const hitWidth = Math.max(1, hit.right - hit.left);
  const hitHeight = Math.max(1, hit.bottom - hit.top);
  const style = (rect: Rect, width: number, height: number) => ({
    left: `${(rect.left / width) * 100}%`,
    top: `${(rect.top / height) * 100}%`,
    width: `${((rect.right - rect.left) / width) * 100}%`,
    height: `${((rect.bottom - rect.top) / height) * 100}%`
  });
  return {
    hit: style(hit, displayWidth, displayHeight),
    visible: style({
      left: exact.left - hit.left,
      top: exact.top - hit.top,
      right: exact.right - hit.left,
      bottom: exact.bottom - hit.top
    }, hitWidth, hitHeight)
  };
}

type PendingAction =
  | (WinActionBinding & {
    kind: "click";
    x: number;
    y: number;
    element: WinElement;
    action: "click" | "double_click" | "right_click" | "scroll";
    deltaX: number;
    deltaY: number;
  })
  | (WinActionBinding & { kind: "type"; text: string })
  | (WinActionBinding & { kind: "key"; key: WinInputKey });

function actionId(): string {
  return typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID() : `winapps-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function elementBounds(element: WinElement): WinActionBinding["elementBounds"] {
  return { x: element.x, y: element.y, w: element.w, h: element.h };
}

const HEADER_END = new TextEncoder().encode("\r\n\r\n");
const CRLF = new TextEncoder().encode("\r\n");
const PNG_SIGNATURE = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const result = new Uint8Array(a.length + b.length);
  result.set(a);
  result.set(b, a.length);
  return result;
}

function validatePngFrame(png: Uint8Array): void {
  if (png.length < 57 || png.length > MAX_STREAM_FRAME_BYTES
    || !PNG_SIGNATURE.every((byte, index) => png[index] === byte)) {
    throw new Error("The mirror stream returned an invalid PNG frame");
  }
  const view = new DataView(png.buffer, png.byteOffset, png.byteLength);
  if (view.getUint32(8) !== 13 || view.getUint32(12) !== 0x49484452
    || view.getUint32(png.length - 12) !== 0 || view.getUint32(png.length - 8) !== 0x49454e44
    || view.getUint32(png.length - 4) !== 0xae426082) {
    throw new Error("The mirror stream returned an invalid PNG frame");
  }
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (!width || !height || width * height > MAX_CAPTURE_PIXELS) {
    throw new Error("The mirror stream returned invalid PNG dimensions");
  }
}

async function pumpPngStream(
  response: Response,
  onFrame: (png: Uint8Array) => void
): Promise<void> {
  if (!response.body) throw new Error("The mirror stream ended");
  const reader = response.body.getReader();
  let pending: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  let frameLength: number | null = null;
  let frameParts: Uint8Array[] = [];
  let frameBytes = 0;
  let expectCrlf = false;
  const decoder = new TextDecoder();
  for (;;) {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const read = await Promise.race([
      reader.read(),
      new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(new Error("The mirror stream stalled")), STREAM_IDLE_TIMEOUT_MS);
      })
    ]).finally(() => {
      if (timeout !== undefined) clearTimeout(timeout);
    });
    if (read.done) {
      if (frameLength !== null || expectCrlf || pending.length) {
        throw new Error("The mirror stream ended during a PNG frame");
      }
      return;
    }

    let input = concatBytes(pending, read.value);
    pending = new Uint8Array(0);
    while (input.length) {
      if (frameLength !== null) {
        const length = Math.min(frameLength - frameBytes, input.length);
        frameParts.push(input.slice(0, length));
        frameBytes += length;
        input = input.slice(length);
        if (frameBytes === frameLength) {
          const frame = new Uint8Array(frameLength);
          let offset = 0;
          for (const part of frameParts) {
            frame.set(part, offset);
            offset += part.length;
          }
          validatePngFrame(frame);
          onFrame(frame);
          frameLength = null;
          frameParts = [];
          frameBytes = 0;
          expectCrlf = true;
        }
        continue;
      }

      if (expectCrlf) {
        if (input.length < 2) {
          pending = input;
          break;
        }
        if (input[0] !== 13 || input[1] !== 10) {
          throw new Error("The mirror stream returned malformed frame data");
        }
        input = input.slice(2);
        expectCrlf = false;
        continue;
      }

      const headerEnd = indexOfBytes(input, HEADER_END, 0);
      if (headerEnd < 0) {
        pending = input;
        if (pending.length > MAX_STREAM_HEADER_BYTES) {
          throw new Error("The mirror stream returned oversized headers");
        }
        break;
      }
      if (headerEnd > MAX_STREAM_HEADER_BYTES) {
        throw new Error("The mirror stream returned oversized headers");
      }
      const header = decoder.decode(input.slice(0, headerEnd));
      const contentType = header.match(/(?:^|\r\n)Content-Type:\s*([^\r\n]+)/i)?.[1]?.trim();
      const rawLength = header.match(/(?:^|\r\n)Content-Length:\s*(\d+)\s*(?:\r\n|$)/i)?.[1];
      const length = rawLength === undefined ? NaN : Number(rawLength);
      if (!header.startsWith("--frame\r\n") || contentType?.toLowerCase() !== "image/png"
        || !Number.isSafeInteger(length) || length < 57 || length > MAX_STREAM_FRAME_BYTES) {
        throw new Error("The mirror stream returned invalid frame headers");
      }
      frameLength = length;
      input = input.slice(headerEnd + HEADER_END.length);
    }
  }
}

function labelFor(app: WinApp): string {
  // A lock instead of a word: option text is not translated, the hint below the picker is.
  if (app.restricted) return `${app.app} \u{1F512}`;
  const title = app.title ? ` — ${app.title.slice(0, 40)}` : "";
  return `${app.app}${title}`;
}

function auditLabel(row: WinAuditRow): string {
  const action = row.action ?? row.kind;
  const labels: Record<string, string> = {
    arm: "Arm control",
    disarm: "Disarm control",
    "panic-stop": "Panic stop",
    click: "Click",
    double_click: "Double-click",
    right_click: "Right-click",
    scroll: "Scroll",
    type: "Type text",
    key: "Press key"
  };
  return labels[action] ?? "Action";
}

function constrainPanel(
  rect: { left: number; top: number; width: number; height: number },
  viewportWidth: number,
  viewportHeight: number
) {
  const margin = 12;
  const maxWidth = Math.max(1, viewportWidth - margin * 2);
  const maxHeight = Math.max(1, viewportHeight - margin * 2);
  const width = clamp(rect.width, Math.min(MIN_WIDTH, maxWidth), maxWidth);
  const height = clamp(rect.height, Math.min(MIN_HEIGHT, maxHeight), maxHeight);
  return {
    left: clamp(rect.left, margin, Math.max(margin, viewportWidth - width - margin)),
    top: clamp(rect.top, margin, Math.max(margin, viewportHeight - height - margin)),
    width,
    height
  };
}

export function WinAppsPanel() {
  const { data, error, reload } = usePoll<WinAppsInfo>(
    () => api.winappsApps(), INVENTORY_INTERVAL
  );
  const control = usePoll<WinControlState>(() => api.winappsControl(), 15000);
  const [windowId, setWindowId] = useState(0);
  const [float, setFloat] = useState(true);
  const [hidden, setHidden] = useState(false);
  const [pos, setPos] = useState({ left: 0, top: 0, width: 440, height: 420 });
  const [showElements, setShowElements] = useState(false);
  const [query, setQuery] = useState("");
  const [mouseAction, setMouseAction] = useState<MouseAction>("click");
  const [scrollDeltaY, setScrollDeltaY] = useState(120);
  const [searchResult, setSearchResult] = useState<{
    windowId: number; windowToken: string; revision: string; query: string; hits: WinElement[];
  } | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [inputText, setInputText] = useState("");
  const [inputKey, setInputKey] = useState<WinInputKey>("tab");
  const [actionError, setActionError] = useState<string | null>(null);
  const [controlBusy, setControlBusy] = useState(false);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [shot, setShot] = useState<string | null>(null);
  const [shotWindowId, setShotWindowId] = useState<number | null>(null);
  const [shotWindowToken, setShotWindowToken] = useState<string | null>(null);
  const [elementsSnapshot, setElementsSnapshot] = useState<WinElementsInfo | null>(null);
  const [mirrorSize, setMirrorSize] = useState({ width: 0, height: 0 });
  const [coarsePointer, setCoarsePointer] = useState(false);
  const [shotError, setShotError] = useState<string | null>(null);
  const [visible, setVisible] = useState(typeof document === "undefined" || !document.hidden);
  const [hovering, setHovering] = useState(false);
  const [streamState, setStreamState] = useState<"on" | "failed">("on");
  const shotRef = useRef<string | null>(null);
  const revisionRef = useRef<string | undefined>(undefined);
  const revisionWindowRef = useRef<number | null>(null);
  const ownerRef = useRef<string>(typeof crypto !== "undefined" && crypto.randomUUID
    ? crypto.randomUUID() : `winapps-${Date.now()}`);
  const ownerArmedRef = useRef(false);
  const selectedWindowIdRef = useRef<number | null>(null);
  const selectedWindowTokenRef = useRef<string | null>(null);
  const streamGenerationRef = useRef(0);
  const displaySequenceRef = useRef(0);
  const snapshotControllerRef = useRef<AbortController | null>(null);
  const snapshotInFlightRef = useRef(false);
  const mirrorRef = useRef<HTMLDivElement | null>(null);
  const elementsRequestRef = useRef<{
    windowId: number; windowToken: string; promise: Promise<WinElementsInfo | null>;
  } | null>(null);

  const windows = data?.windows ?? [];
  // Restricted windows are listed so people know they exist, but are never selected, captured,
  // streamed or sent input; the console refuses them too (console/winapps_guard.py).
  const usable = windows.filter((window) => !window.restricted);
  const selected = usable.find((window) => window.windowId === windowId) ?? usable[0] ?? null;
  selectedWindowIdRef.current = selected?.windowId ?? null;
  selectedWindowTokenRef.current = selected?.windowToken ?? null;
  const requestElementsRef = useRef<() => Promise<WinElementsInfo | null>>(() => Promise.resolve(null));

  const requestElements = useCallback((): Promise<WinElementsInfo | null> => {
    if (!selected) return Promise.resolve(null);
    const target = selected;
    const inFlight = elementsRequestRef.current;
    if (inFlight?.windowId === target.windowId && inFlight.windowToken === target.windowToken) {
      return inFlight.promise;
    }
    if (inFlight) {
      return inFlight.promise.then(
        () => requestElementsRef.current(),
        () => requestElementsRef.current()
      );
    }
    if (revisionWindowRef.current !== target.windowId) {
      revisionWindowRef.current = target.windowId;
      revisionRef.current = undefined;
    }
    let request: Promise<WinElementsInfo | null>;
    request = api.winappsElements(target.windowId, revisionRef.current, target.windowToken).then((result) => {
      if (selectedWindowIdRef.current !== target.windowId
        || selectedWindowTokenRef.current !== target.windowToken
        || result.windowToken !== target.windowToken) return null;
      revisionRef.current = result.revision;
      setElementsSnapshot(result);
      return result;
    }).finally(() => {
      if (elementsRequestRef.current?.promise === request) elementsRequestRef.current = null;
    });
    elementsRequestRef.current = { windowId: target.windowId, windowToken: target.windowToken, promise: request };
    return request;
  }, [selected?.windowId, selected?.windowToken]);
  requestElementsRef.current = requestElements;
  const { data: polledElements, error: elementsError } = usePoll(
    () => showElements ? requestElements() : Promise.resolve(null),
    showElements && !hidden ? ELEMENTS_INTERVAL : 0,
    [showElements, hidden, selected?.windowId, selected?.windowToken, requestElements]
  );
  const elementsData = selected && elementsSnapshot?.windowId === selected.windowId
    && elementsSnapshot.windowToken === selected.windowToken ? elementsSnapshot
    : selected && polledElements?.windowId === selected.windowId
      && polledElements.windowToken === selected.windowToken ? polledElements : null;
  const fps = hovering ? FPS_HOVER : FPS_IDLE;
  const controlState = control.data;
  const armed = controlState?.armed === true;
  const armedByThisPanel = armed && controlState?.owner === ownerRef.current;
  const lockedByOther = armed && !armedByThisPanel;
  const elements = selected && elementsData?.windowId === selected.windowId
    ? elementsData?.elements ?? [] : [];
  const activeSearch = selected && searchResult && searchResult.windowId === selected.windowId
    && searchResult.windowToken === selected.windowToken
    && searchResult.query === query.trim() ? searchResult : null;
  const hitIds = activeSearch ? new Set(activeSearch.hits.map((element) => element.elementId)) : null;
  const visibleElements = hitIds ? elements.filter((element) => hitIds.has(element.elementId)) : elements;
  const recentActions = controlState?.recentActions ?? [];

  useEffect(() => {
    setPending(null);
    setSearchResult(null);
    setSearchError(null);
    setElementsSnapshot(null);
    revisionRef.current = undefined;
    revisionWindowRef.current = selected?.windowId ?? null;
  }, [selected?.windowId, selected?.windowToken]);

  useEffect(() => {
    const initialize = () => setPos((current) => {
      const initial = current.left === 0 && current.top === 0
        ? { ...current, left: Math.max(12, window.innerWidth - 480), top: 220 }
        : current;
      return constrainPanel(initial, window.innerWidth, window.innerHeight);
    });
    const resize = () => setPos((current) => constrainPanel(current, window.innerWidth, window.innerHeight));
    initialize();
    window.addEventListener("resize", resize);
    return () => window.removeEventListener("resize", resize);
  }, []);

  useEffect(() => {
    if (selected && selected.windowId !== windowId) setWindowId(selected.windowId);
  }, [selected, windowId]);

  useEffect(() => {
    displaySequenceRef.current += 1;
    snapshotControllerRef.current?.abort();
    snapshotControllerRef.current = null;
    snapshotInFlightRef.current = false;
    if (shotRef.current) URL.revokeObjectURL(shotRef.current);
    shotRef.current = null;
    setShot(null);
    setShotWindowId(null);
    setShotWindowToken(null);
    setShotError(null);
    setStreamState("on");
  }, [selected?.windowId, selected?.windowToken]);

  useEffect(() => {
    const update = () => setVisible(!document.hidden);
    document.addEventListener("visibilitychange", update);
    return () => document.removeEventListener("visibilitychange", update);
  }, []);

  useEffect(() => {
    const node = mirrorRef.current;
    if (!node) return;
    const observer = new ResizeObserver((entries) => {
      const box = entries[0]?.contentRect;
      if (box) setMirrorSize({ width: box.width, height: box.height });
    });
    observer.observe(node);
    const box = node.getBoundingClientRect();
    setMirrorSize({ width: box.width, height: box.height });
    return () => observer.disconnect();
  }, [selected?.windowId, selected?.windowToken]);

  useEffect(() => {
    const query = window.matchMedia("(pointer: coarse)");
    const update = () => setCoarsePointer(query.matches);
    update();
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);

  const disarmOwnedLock = useCallback(() => {
    if (!ownerArmedRef.current) return;
    ownerArmedRef.current = false;
    void fetch("/api/labs/winapps/control", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-OSLab": "1" },
        body: JSON.stringify({ armed: false, owner: ownerRef.current }),
        keepalive: true
      }).catch(() => {
        ownerArmedRef.current = true;
      });
  }, []);

  useEffect(() => {
    window.addEventListener("pagehide", disarmOwnedLock);
    return () => {
      window.removeEventListener("pagehide", disarmOwnedLock);
      disarmOwnedLock();
    };
  }, [disarmOwnedLock]);

  const setShotFromBytes = useCallback((
    targetWindowId: number,
    targetWindowToken: string,
    png: Uint8Array,
    isCurrent: () => boolean
  ) => {
    if (!isCurrent() || selectedWindowIdRef.current !== targetWindowId
      || selectedWindowTokenRef.current !== targetWindowToken) return;
    validatePngFrame(png);
    const url = URL.createObjectURL(new Blob([png.slice().buffer as ArrayBuffer], { type: "image/png" }));
    if (shotRef.current) URL.revokeObjectURL(shotRef.current);
    shotRef.current = url;
    setShot(url);
    setShotWindowId(targetWindowId);
    setShotWindowToken(targetWindowToken);
    setShotError(null);
  }, []);

  const grab = useCallback(async () => {
    const targetWindowId = selected?.windowId;
    const targetWindowToken = selected?.windowToken;
    if (!targetWindowId || !targetWindowToken || hidden || snapshotInFlightRef.current) return;
    snapshotInFlightRef.current = true;
    const sequence = ++displaySequenceRef.current;
    const controller = new AbortController();
    snapshotControllerRef.current = controller;
    const timeout = setTimeout(() => controller.abort(), STREAM_CONNECT_TIMEOUT_MS);
    try {
      const response = await fetch(api.winappsAppScreenshotUrl(targetWindowId, targetWindowToken), {
        cache: "no-store",
        signal: controller.signal
      });
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as { error?: string };
        throw new Error(body.error || `${response.status} ${response.statusText}`);
      }
      const png = new Uint8Array(await response.arrayBuffer());
      setShotFromBytes(targetWindowId, targetWindowToken, png, () =>
        sequence === displaySequenceRef.current && selectedWindowIdRef.current === targetWindowId
        && selectedWindowTokenRef.current === targetWindowToken
      );
    } catch (e) {
      if (sequence !== displaySequenceRef.current || selectedWindowIdRef.current !== targetWindowId
        || selectedWindowTokenRef.current !== targetWindowToken) return;
      setShot(null);
      setShotWindowId(null);
      setShotWindowToken(null);
      setShotError(message(e));
    } finally {
      clearTimeout(timeout);
      if (snapshotControllerRef.current === controller) {
        snapshotControllerRef.current = null;
        snapshotInFlightRef.current = false;
      }
    }
  }, [hidden, selected?.windowId, selected?.windowToken, setShotFromBytes]);

  useEffect(() => () => {
    if (shotRef.current) URL.revokeObjectURL(shotRef.current);
  }, []);

  useEffect(() => {
    if (!selected || hidden) return;
    setStreamState("on");
    void grab();
  }, [selected?.windowId, selected?.windowToken, hidden, grab]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selected || hidden || streamState !== "failed") return;
    const timer = setInterval(() => {
      if (!document.hidden) void grab();
    }, MIRROR_INTERVAL);
    return () => clearInterval(timer);
  }, [selected?.windowId, selected?.windowToken, hidden, streamState, grab]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selected || hidden || streamState !== "on" || !visible) return;
    const targetWindowId = selected.windowId;
    const targetWindowToken = selected.windowToken;
    const generation = ++streamGenerationRef.current;
    let active = true;
    let connected = false;
    let timedOut = false;
    const controller = new AbortController();
    const connectionTimer = setTimeout(() => {
      if (!connected) {
        timedOut = true;
        controller.abort();
      }
    }, STREAM_CONNECT_TIMEOUT_MS);
    (async () => {
      try {
        const response = await fetch(api.winappsAppStreamUrl(targetWindowId, fps, targetWindowToken), {
          signal: controller.signal,
          cache: "no-store"
        });
        connected = true;
        clearTimeout(connectionTimer);
        if (!response.ok) {
          const body = (await response.json().catch(() => ({}))) as { error?: string };
          throw new Error(body.error || `${response.status} ${response.statusText}`);
        }
        await pumpPngStream(response, (png) => {
          if (!active || streamGenerationRef.current !== generation
            || selectedWindowIdRef.current !== targetWindowId
            || selectedWindowTokenRef.current !== targetWindowToken) return;
          const sequence = ++displaySequenceRef.current;
          setShotFromBytes(targetWindowId, targetWindowToken, png, () =>
            active && streamGenerationRef.current === generation
            && selectedWindowIdRef.current === targetWindowId
            && selectedWindowTokenRef.current === targetWindowToken
            && displaySequenceRef.current === sequence
          );
        });
        throw new Error("The mirror stream ended");
      } catch (e) {
        if (!active || streamGenerationRef.current !== generation
          || selectedWindowIdRef.current !== targetWindowId
          || selectedWindowTokenRef.current !== targetWindowToken) return;
        controller.abort();
        setShotError(timedOut ? "The mirror stream connection timed out" : message(e));
        setStreamState("failed");
      }
    })();
    return () => {
      active = false;
      clearTimeout(connectionTimer);
      controller.abort();
      if (streamGenerationRef.current === generation) streamGenerationRef.current += 1;
    };
  }, [selected?.windowId, selected?.windowToken, hidden, streamState, visible, fps, setShotFromBytes]);

  const searchElements = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selected) return;
    setShowElements(true);
    setSearchError(null);
    const target = selected;
    try {
      const result = await api.winappsSearch(target.windowId, query, target.windowToken);
      if (selectedWindowIdRef.current !== target.windowId
        || selectedWindowTokenRef.current !== target.windowToken
        || result.windowToken !== target.windowToken) return;
      setSearchResult({
        windowId: result.windowId, windowToken: result.windowToken, revision: result.revision,
        query: result.query, hits: result.hits
      });
    } catch (e) {
      setSearchResult(null);
      setSearchError(message(e));
    }
  };

  const toggleControl = async () => {
    if (controlBusy || lockedByOther) return;
    setControlBusy(true);
    setActionError(null);
    try {
      const nextArmed = !armedByThisPanel;
      await api.winappsControlArm(nextArmed, ownerRef.current);
      ownerArmedRef.current = nextArmed;
      control.reload();
    } catch (e) {
      setActionError(message(e));
    } finally {
      setControlBusy(false);
    }
  };

  const panicStop = async () => {
    setControlBusy(true);
    setActionError(null);
    try {
      await api.winappsStop();
      ownerArmedRef.current = false;
      setPending(null);
      control.reload();
    } catch (e) {
      setActionError(message(e));
    } finally {
      setControlBusy(false);
    }
  };

  const actionBinding = (snapshot: WinElementsInfo, element: WinElement): WinActionBinding => ({
    windowId: snapshot.windowId,
    windowToken: snapshot.windowToken,
    revision: snapshot.revision,
    elementId: element.elementId,
    elementBounds: elementBounds(element),
    owner: ownerRef.current,
    actionId: actionId(),
    confirm: true
  });

  const previewClick = async (x: number, y: number, preferred?: WinElement) => {
    if (!selected || !shot) return;
    const targetWindow = selected;
    setPreviewBusy(true);
    setActionError(null);
    try {
      const snapshot = await requestElements();
      if (!snapshot || snapshot.windowId !== targetWindow.windowId
        || snapshot.windowToken !== targetWindow.windowToken
        || selectedWindowIdRef.current !== targetWindow.windowId
        || selectedWindowTokenRef.current !== targetWindow.windowToken) {
        throw new Error("The selected window changed; refresh the mirror and preview again.");
      }
      const candidates = snapshot.elements.filter((element) => {
        if (!element.enabled) return false;
        if (preferred) return element.elementId === preferred.elementId;
        return x >= element.x && x <= element.x + element.w
          && y >= element.y && y <= element.y + element.h;
      }).sort((a, b) => a.w * a.h - b.w * b.h);
      const element = candidates[0];
      if (!element) throw new Error("Select a visible UI Automation hotspot before previewing a click.");
      if (preferred && (preferred.x !== element.x || preferred.y !== element.y
        || preferred.w !== element.w || preferred.h !== element.h)) {
        throw new Error("The UI Automation control moved; select it again before previewing.");
      }
      const deltaY = mouseAction === "scroll" ? clamp(scrollDeltaY, -MAX_SCROLL_DELTA, MAX_SCROLL_DELTA) : 0;
      if (mouseAction === "scroll" && deltaY === 0) {
        throw new Error("Choose a non-zero scroll amount before previewing.");
      }
      setPending({
        ...actionBinding(snapshot, element),
        kind: "click",
        x: Math.round(element.x + element.w / 2),
        y: Math.round(element.y + element.h / 2),
        element,
        action: mouseAction,
        deltaX: 0,
        deltaY
      });
    } catch (e) {
      setActionError(message(e));
    } finally {
      setPreviewBusy(false);
    }
  };

  const previewInput = async (kind: "type" | "key") => {
    if (!selected) return;
    const targetWindow = selected;
    setPreviewBusy(true);
    setActionError(null);
    try {
      const snapshot = await requestElements();
      if (!snapshot || snapshot.windowId !== targetWindow.windowId
        || snapshot.windowToken !== targetWindow.windowToken
        || selectedWindowIdRef.current !== targetWindow.windowId
        || selectedWindowTokenRef.current !== targetWindow.windowToken) {
        throw new Error("The selected window changed; refresh the mirror and preview again.");
      }
      const element = snapshot.elements.find((candidate) => candidate.focused && candidate.enabled);
      if (!element) throw new Error("Focus a visible UI Automation control before previewing keyboard input.");
      const binding = actionBinding(snapshot, element);
      setPending(kind === "type"
        ? { ...binding, kind, text: inputText }
        : { ...binding, kind, key: inputKey });
    } catch (e) {
      setActionError(message(e));
    } finally {
      setPreviewBusy(false);
    }
  };

  const confirmPending = async () => {
    if (!pending || !armedByThisPanel || controlBusy || !selected
      || pending.windowId !== selected.windowId || pending.windowToken !== selected.windowToken) return;
    setControlBusy(true);
    setActionError(null);
    const binding: WinActionBinding = {
      windowId: pending.windowId,
      windowToken: pending.windowToken,
      revision: pending.revision,
      elementId: pending.elementId,
      elementBounds: pending.elementBounds,
      owner: ownerRef.current,
      actionId: pending.actionId,
      confirm: true
    };
    try {
      if (pending.kind === "click") {
        await api.winappsClick({
          ...binding, x: pending.x, y: pending.y,
          action: pending.action, deltaX: pending.deltaX, deltaY: pending.deltaY
        });
      } else if (pending.kind === "type") {
        await api.winappsInput({
          ...binding, kind: "type", text: pending.text
        });
      } else {
        await api.winappsInput({
          ...binding, kind: "key", key: pending.key
        });
      }
      setPending(null);
      control.reload();
      if (showElements) void requestElements();
    } catch (e) {
      setActionError(message(e));
      control.reload();
    } finally {
      setControlBusy(false);
    }
  };

  const hideMirror = async () => {
    if (armedByThisPanel) {
      setControlBusy(true);
      try {
        await api.winappsControlArm(false, ownerRef.current);
        ownerArmedRef.current = false;
        control.reload();
      } catch (e) {
        setActionError(message(e));
        setControlBusy(false);
        return;
      }
      setControlBusy(false);
    }
    setPending(null);
    setHidden(true);
  };

  const startDrag = (event: React.PointerEvent) => {
    if (!float || (event.target instanceof Element && event.target.closest("button"))) return;
    event.preventDefault();
    const origin = { x: event.clientX, y: event.clientY, left: pos.left, top: pos.top };
    const move = (pointer: PointerEvent) => {
      setPos((current) => ({
        ...current,
        left: clamp(origin.left + pointer.clientX - origin.x, 12,
          Math.max(12, window.innerWidth - current.width - 12)),
        top: clamp(origin.top + pointer.clientY - origin.y, 12,
          Math.max(12, window.innerHeight - current.height - 12))
      }));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const startResize = (event: React.PointerEvent) => {
    if (!float) return;
    event.preventDefault();
    event.stopPropagation();
    const origin = { x: event.clientX, y: event.clientY, width: pos.width, height: pos.height };
    const move = (pointer: PointerEvent) => {
      setPos((current) => {
        const maxWidth = Math.max(1, window.innerWidth - current.left - 12);
        const maxHeight = Math.max(1, window.innerHeight - current.top - 12);
        return {
          ...current,
          width: clamp(origin.width + pointer.clientX - origin.x, Math.min(MIN_WIDTH, maxWidth), maxWidth),
          height: clamp(origin.height + pointer.clientY - origin.y, Math.min(MIN_HEIGHT, maxHeight), maxHeight)
        };
      });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const header = (
    <div
      className={`flex flex-wrap items-center gap-2 border-b border-(--iux-border) px-4 py-2.5 ${float ? "cursor-move touch-none select-none" : ""}`}
      onPointerDown={startDrag}
    >
      <EyeIcon size={15} className="text-[#f36c21]" aria-hidden />
      <span className="text-sm font-semibold">App mirror</span>
      <span className="ml-auto flex items-center gap-1">
        <button
          type="button"
          className="iux-btn"
          data-variant="ghost"
          title={float ? "Dock the panel" : "Float the panel"}
          aria-label={float ? "Dock the panel" : "Float the panel"}
          onClick={() => setFloat((current) => !current)}
        >
          <PushPinIcon size={14} />
        </button>
        <button
          type="button"
          className="iux-btn"
          data-variant="ghost"
          title="Hide the app mirror"
          aria-label="Hide the app mirror"
          onClick={() => void hideMirror()}
        >
          <XIcon size={14} />
        </button>
      </span>
    </div>
  );

  const currentShot = selected && shotWindowId === selected.windowId
    && shotWindowToken === selected.windowToken ? shot : null;
  const body = (
    <div className="flex flex-col gap-3">
      {error ? <Status value={{ ok: false, text: error }} /> : null}
      {control.error ? <Status value={{ ok: false, text: control.error }} /> : null}
      {actionError ? <Status value={{ ok: false, text: actionError }} /> : null}
      {elementsError ? <Status value={{ ok: false, text: elementsError }} /> : null}
      {searchError ? <Status value={{ ok: false, text: searchError }} /> : null}
      {streamState === "failed" && shotError ? <Status value={{ ok: false, text: shotError }} /> : null}
      {!data ? (
        <Skeleton rows={2} />
      ) : !data.available ? (
        <Empty>{data.reason ?? "The Windows app mirror is not available here."}</Empty>
      ) : windows.length === 0 ? (
        <Empty>No visible desktop application windows were found.</Empty>
      ) : usable.length === 0 ? (
        <Empty>Some windows are restricted and cannot be mirrored.</Empty>
      ) : selected ? (
        <>
          <Field label="Window">
            <select
              className="iux-input"
              value={selected.windowId}
              onChange={(event) => setWindowId(Number(event.target.value))}
              aria-label="Window"
            >
              {windows.map((window) => (
                <option key={window.windowId} value={window.windowId} disabled={window.restricted}>{labelFor(window)}</option>
              ))}
            </select>
          </Field>
          {usable.length < windows.length ? (
            <p className="text-xs text-(--iux-muted-foreground)">Some windows are restricted and cannot be mirrored.</p>
          ) : null}
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="iux-btn" data-variant="outline" onClick={() => {
              reload();
              void grab();
            }}>
              <ArrowClockwiseIcon size={14} /> Refresh
            </button>
            <button type="button" className="iux-btn" data-variant={showElements ? undefined : "outline"}
              aria-pressed={showElements} onClick={() => {
                setShowElements((current) => !current);
                if (!showElements) void requestElements().catch((e) => setActionError(message(e)));
              }}>
              <EyeIcon size={14} /> Elements
            </button>
            <button type="button" className={armedByThisPanel ? "iux-btn bg-[#f36c21] text-white hover:bg-[#fa7b32]" : "iux-btn"}
              data-variant={armedByThisPanel ? undefined : "outline"} aria-pressed={armedByThisPanel}
              disabled={controlBusy || lockedByOther} onClick={() => void toggleControl()}>
              <HandIcon size={14} /> {lockedByOther ? "Control locked" : armedByThisPanel ? "Disarm control" : "Arm control"}
            </button>
            <button type="button" className="iux-btn" data-variant="outline" disabled={controlBusy}
              title="Panic stop disarms input and ends active mirror streams"
              onClick={() => void panicStop()}>
              Panic stop
            </button>
            <Badge tone={selected.width > 0 && selected.height > 0 ? "success" : "warning"}>
              {`${selected.width}×${selected.height}`}
            </Badge>
            {selected.elevated ? <Badge tone="warning">Elevated</Badge> : null}
          </div>
          {lockedByOther ? (
            <Status value={{ ok: false, text: "Another dashboard owns the Windows app control lock." }} />
          ) : armedByThisPanel ? (
            <Status value={{ ok: true, text: "Control is armed. Actions still require preview confirmation." }} />
          ) : null}
          {showElements ? (
            <>
              <form className="flex gap-2" onSubmit={(event) => void searchElements(event)}>
                <input className="iux-input min-w-0 flex-1" value={query} maxLength={120}
                  aria-label="Search elements" placeholder="Search elements"
                  onChange={(event) => {
                    setQuery(event.target.value);
                    setSearchResult(null);
                    setSearchError(null);
                  }} />
                <button type="submit" className="iux-btn" data-variant="outline">Search</button>
              </form>
              <p className="text-xs text-(--iux-muted-foreground)">
                {activeSearch ? <>{activeSearch.hits.length} <span>matches</span></> : <>{elements.length} <span>UI Automation elements</span></>}
                {elementsData?.trimmed ? <> · <span>UI Automation list trimmed</span></> : ""}
              </p>
            </>
          ) : null}
          <div className="grid gap-2 sm:grid-cols-2">
            <Field label="Mouse action">
              <select className="iux-input" value={mouseAction} aria-label="Mouse action"
                onChange={(event) => setMouseAction(event.target.value as MouseAction)}>
                {MOUSE_ACTIONS.map((action) => (
                  <option key={action} value={action}>{MOUSE_ACTION_LABELS[action]}</option>
                ))}
              </select>
            </Field>
            {mouseAction === "scroll" ? (
              <Field label="Scroll amount">
                <input className="iux-input" type="number" min={-MAX_SCROLL_DELTA} max={MAX_SCROLL_DELTA}
                  step={120} value={scrollDeltaY} aria-label="Scroll amount"
                  onChange={(event) => {
                    const value = Number(event.target.value);
                    setScrollDeltaY(Number.isFinite(value) ? clamp(value, -MAX_SCROLL_DELTA, MAX_SCROLL_DELTA) : 0);
                  }} />
              </Field>
            ) : null}
            <div className="flex items-end gap-2">
              <Field label="Text to type">
                <input className="iux-input" value={inputText} maxLength={200} aria-label="Text to type"
                  onChange={(event) => setInputText(event.target.value)} />
              </Field>
              <button type="button" className="iux-btn shrink-0" data-variant="outline"
                disabled={!inputText.length || previewBusy} onClick={() => void previewInput("type")}>
                Preview text
              </button>
            </div>
            <div className="flex items-end gap-2">
              <Field label="Key to press">
                <select className="iux-input" value={inputKey} aria-label="Key to press"
                  onChange={(event) => setInputKey(event.target.value as WinInputKey)}>
                  {INPUT_KEYS.map((key) => <option key={key} value={key}>{key}</option>)}
                </select>
              </Field>
              <button type="button" className="iux-btn shrink-0" data-variant="outline"
                disabled={previewBusy} onClick={() => void previewInput("key")}>
                Preview key
              </button>
            </div>
          </div>
          {((controlState?.recentActions?.length ?? 0) > 0 || (controlState?.audit?.length ?? 0) > 0) ? (
            <section aria-label="Recent actions" className="rounded-lg border border-(--iux-border) p-2">
              <h3 className="mb-1 text-xs font-semibold">Recent actions</h3>
              <ol className="flex flex-col gap-1">
                {(controlState?.recentActions ?? controlState?.audit ?? []).slice(-6).reverse().map((row, index) => (
                  <li key={`${row.time}-${row.kind}-${index}`} className="flex items-center gap-2 text-xs">
                    <span className="min-w-0 flex-1 truncate">
                      {auditLabel(row)}{row.key ? ` · ${row.key}` : ""}{row.app ? ` · ${row.app}` : ""}
                    </span>
                    <span className={row.ok === false ? "text-(--iux-danger)" : "text-(--iux-muted-foreground)"}>
                      {row.ok === false ? "Blocked" : "Sent"}
                    </span>
                    <time dateTime={new Date(row.time * 1000).toISOString()}>
                      {new Date(row.time * 1000).toLocaleTimeString()}
                    </time>
                  </li>
                ))}
              </ol>
            </section>
          ) : null}
          <div
            ref={mirrorRef}
            className="relative w-full cursor-crosshair overflow-hidden rounded-xl border border-(--iux-border) bg-black"
            style={{
              aspectRatio: `${selected.width || 4} / ${selected.height || 3}`,
              maxWidth: `calc(70vh * ${selected.width || 4} / ${selected.height || 3})`,
              marginInline: "auto"
            }}
            onClick={(event) => {
              const rect = event.currentTarget.getBoundingClientRect();
              if (!rect.width || !rect.height) return;
              void previewClick(
                (event.clientX - rect.left) * selected.width / rect.width,
                (event.clientY - rect.top) * selected.height / rect.height
              );
            }}
            onPointerEnter={() => setHovering(true)}
            onPointerLeave={() => setHovering(false)}
          >
            {currentShot ? (
              <img
                src={currentShot}
                alt={`Mirror of ${selected.app}`}
                className="absolute inset-0 h-full w-full object-fill"
                draggable={false}
              />
            ) : shotError ? (
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-4 text-center">
                <p className="text-xs text-zinc-400">{shotError}</p>
                <button
                  type="button"
                  className="iux-btn"
                  data-variant="outline"
                  onClick={() => {
                    setStreamState("on");
                    setShotError(null);
                    void grab();
                  }}
                >
                  Retry
                </button>
              </div>
            ) : (
              <div className="absolute inset-0 flex items-center justify-center" aria-busy="true">
                <CircleNotchIcon size={22} className="animate-spin text-zinc-500" aria-hidden />
              </div>
            )}
            {showElements && currentShot ? visibleElements.map((element, index) => (
              (() => {
                const styles = hotspotStyles(element, elements, selected, mirrorSize, coarsePointer);
                return (
                  <button
                    key={element.elementId}
                    type="button"
                    data-testid="winapps-hotspot"
                    data-element-id={element.elementId}
                    className="absolute z-10 rounded-md border-0 bg-transparent p-0"
                    style={styles.hit}
                    title={`${element.role}${element.label ? `: ${element.label}` : ""}`}
                    aria-label={`${element.role}${element.label ? `: ${element.label}` : ""}`}
                    onClick={(event) => {
                      event.stopPropagation();
                      void previewClick(element.x + element.w / 2, element.y + element.h / 2, element);
                    }}
                  >
                    <span
                      data-testid="winapps-hotspot-visible"
                      data-element-id={element.elementId}
                      aria-hidden="true"
                      className={`absolute flex items-center justify-center rounded-md border text-[10px] font-semibold pointer-events-none ${
                        element.focused
                          ? "border-violet-400/80 bg-violet-400/20 text-violet-100"
                          : element.enabled
                            ? "border-[#f36c21]/80 bg-[#f36c21]/20 text-[#ffcfaa]"
                            : "border-zinc-400/70 bg-zinc-400/15 text-zinc-300"
                      }`}
                      style={styles.visible}
                    >
                      {element.w > 24 && element.h > 14 ? index + 1 : null}
                    </span>
                  </button>
                );
              })()
            )) : null}
          </div>
          {showElements && !elements.length && !elementsError ? (
            <Empty>No UI Automation elements were returned for this window.</Empty>
          ) : null}
        </>
      ) : null}
    </div>
  );

  const actionDialog = pending ? (
    <Modal title="Review action" icon={<CrosshairIcon size={16} />}
      description="Review the target before sending input to the selected Windows window."
      onClose={() => setPending(null)}>
      <div className="flex flex-col gap-3 px-6 pb-5">
        <p className="text-sm font-medium">
          {pending.kind === "click" ? (
            <>
              <span>{pending.action === "double_click" ? "Double-click UI element"
                : pending.action === "right_click" ? "Right-click UI element"
                  : pending.action === "scroll" ? "Scroll UI element" : "Click UI element"}: </span>
              {pending.element.role}{pending.element.label ? `: ${pending.element.label}` : ""}
            </>
          ) : pending.kind === "type" ? (
            <span>Type this text into the focused control</span>
          ) : (
            <><span>Press key</span> <code>{pending.key}</code></>
          )}
        </p>
        {pending.kind === "click" && pending.action === "scroll" ? (
          <p className="text-xs">{`Scroll delta: ${pending.deltaY}`}</p>
        ) : null}
        {pending.kind === "type" ? (
          <pre className="max-h-32 overflow-auto whitespace-pre-wrap rounded-md border border-(--iux-border) p-3 text-xs">{pending.text}</pre>
        ) : null}
        {pending.kind === "key" && pending.key === "enter" ? (
          <p className="text-xs text-(--iux-danger)">Enter can submit forms or send messages. Confirm only if that is intended.</p>
        ) : null}
        {!armedByThisPanel ? (
          <Status value={{ ok: false, text: lockedByOther
            ? "Another dashboard owns the Windows app control lock."
            : "Arm control before confirming this action." }} />
        ) : null}
        {actionError ? <Status value={{ ok: false, text: actionError }} /> : null}
        <div className="flex justify-end gap-2">
          <button type="button" className="iux-btn" data-variant="outline" onClick={() => setPending(null)}>Cancel</button>
          <button type="button" className="iux-btn bg-[#f36c21] text-white hover:bg-[#fa7b32]"
            disabled={!armedByThisPanel || controlBusy} onClick={() => void confirmPending()}>
            {controlBusy ? "Sending…" : "Confirm and send"}
          </button>
        </div>
      </div>
    </Modal>
  ) : null;

  if (hidden) {
    return (
      <section className="iux-card items-start gap-3 py-4">
        <div className="flex items-center gap-2 px-4">
          <EyeIcon size={15} className="text-[#f36c21]" aria-hidden />
          <span className="text-sm font-semibold">App mirror</span>
        </div>
        <div className="px-4">
          <button type="button" className="iux-btn" data-variant="outline" onClick={() => setHidden(false)}>
            Show the app mirror
          </button>
        </div>
      </section>
    );
  }

  return float ? (
    <div
      className="iux-card fixed z-40 flex flex-col overflow-hidden shadow-[0_18px_50px_-12px_rgba(0,0,0,0.55)]"
      style={{
        left: pos.left, top: pos.top, width: pos.width, height: pos.height,
        maxWidth: "calc(100vw - 24px)", maxHeight: "calc(100dvh - 24px)"
      }}
    >
      {header}
      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">{body}</div>
      <div
        className="absolute right-0 bottom-0 h-5 w-5 cursor-nwse-resize touch-none"
        onPointerDown={startResize}
        aria-hidden
      />
      {actionDialog}
    </div>
  ) : (
    <section className="iux-card gap-3 py-4">
      {header}
      <div className="px-4">{body}</div>
      {actionDialog}
    </section>
  );
}
