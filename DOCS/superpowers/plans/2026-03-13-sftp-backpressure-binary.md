# SFTP Download Backpressure & Binary Transfer

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix large SFTP download disconnections (issue #492) by adding backpressure control and switching from base64 to native binary transfer.

**Architecture:** Extract shared backpressure utilities from the terminal adapter into a reusable module. Apply backpressure to SFTP download chunk emission using an async callback pattern. Replace base64 string encoding with raw `Buffer`/`Uint8Array` binary transport on both server and client sides.

**Tech Stack:** Node.js Buffer, Socket.IO 4.x native binary support, Vitest, SolidJS client

**Related Issue:** <https://github.com/billchurch/webssh2/issues/492>

---

## File Structure

| Action | File | Responsibility |
| --- | --- | --- |
| Create | `app/socket/backpressure.ts` | Shared backpressure utilities (extracted from terminal adapter) |
| Create | `tests/unit/backpressure.vitest.ts` | Tests for shared backpressure module |
| Modify | `app/socket/adapters/service-socket-terminal.ts` | Import from shared module instead of local definitions |
| Modify | `app/services/sftp/sftp-service.ts:108-115,751-805` | Change `DownloadChunkData.data` from `string` to `Buffer`; make `onChunk` async for backpressure |
| Modify | `app/socket/adapters/service-socket-sftp.ts:464-496` | Add backpressure check around chunk emission |
| Modify | `webssh2_client/client/src/types/sftp.ts:231-240` | Change `SftpDownloadChunkResponse.data` from `string` to `ArrayBuffer` |
| Modify | `webssh2_client/client/src/utils/download-assembler.ts:17-56,158-171` | Accept `Uint8Array` directly instead of base64 decoding |
| Modify | `webssh2_client/client/src/services/sftp-service.ts:363-391` | Pass binary data to assembler |
| Modify | `tests/unit/stream-backpressure.vitest.ts` | Update imports to shared module |

---

## Chunk 1: Extract Shared Backpressure Module

### Task 1: Create shared backpressure module with tests

**Files:**

- Create: `app/socket/backpressure.ts`
- Create: `tests/unit/backpressure.vitest.ts`

- [ ] **Step 1: Write failing tests for the shared module**

Create `tests/unit/backpressure.vitest.ts` with tests that import from the new shared location. These are essentially the same pure-function tests from `tests/unit/stream-backpressure.vitest.ts` for `computeBackpressureAction` and `getWebSocketBufferedBytes`, but importing from `app/socket/backpressure.ts`.

```typescript
// tests/unit/backpressure.vitest.ts
import { describe, it, expect, vi } from 'vitest'
import {
  getWebSocketBufferedBytes,
  computeBackpressureAction,
  createBackpressureController,
  type BackpressureSocket
} from '../../app/socket/backpressure.js'

describe('computeBackpressureAction', () => {
  const HWM = 16384
  const LWM = Math.floor(HWM / 4) // 4096

  it('returns "none" when bufferedBytes is null', () => {
    expect(computeBackpressureAction(null, HWM, false)).toBe('none')
    expect(computeBackpressureAction(null, HWM, true)).toBe('none')
  })

  it('returns "pause" when buffer >= HWM and not paused', () => {
    expect(computeBackpressureAction(HWM, HWM, false)).toBe('pause')
    expect(computeBackpressureAction(HWM + 1000, HWM, false)).toBe('pause')
  })

  it('returns "none" when buffer < HWM and not paused', () => {
    expect(computeBackpressureAction(0, HWM, false)).toBe('none')
    expect(computeBackpressureAction(HWM - 1, HWM, false)).toBe('none')
  })

  it('returns "resume" when buffer < LWM and paused', () => {
    expect(computeBackpressureAction(0, HWM, true)).toBe('resume')
    expect(computeBackpressureAction(LWM - 1, HWM, true)).toBe('resume')
  })

  it('returns "none" when paused but buffer between LWM and HWM (hysteresis)', () => {
    expect(computeBackpressureAction(LWM, HWM, true)).toBe('none')
    expect(computeBackpressureAction(HWM - 1, HWM, true)).toBe('none')
  })

  it('returns "none" when already paused and still above HWM', () => {
    expect(computeBackpressureAction(HWM, HWM, true)).toBe('none')
    expect(computeBackpressureAction(HWM + 5000, HWM, true)).toBe('none')
  })
})

describe('getWebSocketBufferedBytes', () => {
  function makeSocket(opts?: {
    bufferedAmount?: number
    transportName?: string
  }): BackpressureSocket {
    return {
      conn: {
        transport: {
          name: opts?.transportName ?? 'websocket',
          socket: { bufferedAmount: opts?.bufferedAmount ?? 0 }
        },
        once: vi.fn(),
        removeListener: vi.fn()
      } as never
    } as BackpressureSocket
  }

  it('returns bufferedAmount when transport is websocket', () => {
    expect(getWebSocketBufferedBytes(makeSocket({ bufferedAmount: 12345 }))).toBe(12345)
  })

  it('returns null when transport is not websocket', () => {
    expect(getWebSocketBufferedBytes(makeSocket({ transportName: 'polling' }))).toBeNull()
  })

  it('returns 0 when buffer is empty', () => {
    expect(getWebSocketBufferedBytes(makeSocket({ bufferedAmount: 0 }))).toBe(0)
  })
})

describe('createBackpressureController', () => {
  it('waitForDrain resolves immediately when buffer is below HWM', async () => {
    const socket = {
      conn: {
        transport: {
          name: 'websocket',
          socket: { bufferedAmount: 100 }
        },
        once: vi.fn(),
        removeListener: vi.fn()
      } as never
    } as BackpressureSocket

    const controller = createBackpressureController(socket, 16384)
    await controller.waitForDrain()
    // Should resolve without blocking
    controller.destroy()
  })

  it('waitForDrain blocks when buffer exceeds HWM', async () => {
    let currentBuffered = 20000
    const listeners: Map<string, () => void> = new Map()
    const conn = {
      transport: {
        name: 'websocket',
        socket: { get bufferedAmount() { return currentBuffered } }
      },
      once: vi.fn((event: string, cb: () => void) => { listeners.set(event, cb) }),
      removeListener: vi.fn()
    }
    const socket = { conn } as unknown as BackpressureSocket

    const controller = createBackpressureController(socket, 16384)
    let resolved = false
    const promise = controller.waitForDrain().then(() => { resolved = true })

    // Should not resolve yet
    await Promise.resolve()
    expect(resolved).toBe(false)

    // Simulate buffer draining
    currentBuffered = 1000
    const drainCb = listeners.get('drain')
    if (drainCb) drainCb()

    await promise
    expect(resolved).toBe(true)
    controller.destroy()
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npx vitest run tests/unit/backpressure.vitest.ts`
Expected: FAIL — module `app/socket/backpressure.ts` does not exist

- [ ] **Step 3: Create the shared backpressure module**

Extract `getWebSocketBufferedBytes` and `computeBackpressureAction` from `service-socket-terminal.ts` into a new shared module. Add a new `createBackpressureController` factory that encapsulates the drain-wait pattern for use by SFTP.

```typescript
// app/socket/backpressure.ts
/**
 * Shared WebSocket backpressure utilities.
 *
 * Extracted from service-socket-terminal to be reused by SFTP downloads
 * and any future high-throughput socket emitters.
 *
 * @module socket/backpressure
 */

const LOW_WATER_MARK_DIVISOR = 4
const DRAIN_POLL_MS = 50

/** Minimal socket shape needed for backpressure checks */
export type BackpressureSocket = {
  conn: {
    once(event: string, cb: () => void): void
    removeListener(event: string, cb: () => void): void
  } & Record<string, unknown>
} & Record<string, unknown>

/**
 * Safely reads bufferedAmount from the ws WebSocket via the Engine.IO
 * transport chain. Returns null when unavailable (polling transport,
 * access failure, or during transport upgrade).
 */
export function getWebSocketBufferedBytes(
  socket: BackpressureSocket
): number | null {
  try {
    const conn: unknown = socket.conn
    if (typeof conn !== 'object' || conn === null) {
      return null
    }
    const transport: unknown = (conn as Record<string, unknown>)['transport']
    if (typeof transport !== 'object' || transport === null) {
      return null
    }
    const transportRecord = transport as Record<string, unknown>
    if (transportRecord['name'] !== 'websocket') {
      return null
    }
    const wsSocket: unknown = transportRecord['socket']
    if (typeof wsSocket !== 'object' || wsSocket === null) {
      return null
    }
    const amount: unknown = (wsSocket as Record<string, unknown>)['bufferedAmount']
    if (typeof amount !== 'number') {
      return null
    }
    return amount
  } catch {
    return null
  }
}

/**
 * Pure decision function for backpressure control.
 * Returns 'pause' when buffer exceeds high water mark,
 * 'resume' when buffer drops below low water mark (HWM / 4),
 * or 'none' when no action is needed.
 */
export function computeBackpressureAction(
  bufferedBytes: number | null,
  highWaterMark: number,
  currentlyPaused: boolean
): 'pause' | 'resume' | 'none' {
  if (bufferedBytes === null) {
    return 'none'
  }
  const lowWaterMark = Math.floor(highWaterMark / LOW_WATER_MARK_DIVISOR)
  if (!currentlyPaused && bufferedBytes >= highWaterMark) {
    return 'pause'
  }
  if (currentlyPaused && bufferedBytes < lowWaterMark) {
    return 'resume'
  }
  return 'none'
}

/**
 * Controller that provides an async waitForDrain() method.
 * Callers await this between emits to respect WebSocket backpressure.
 */
export interface BackpressureController {
  /** Resolves immediately if buffer is OK, otherwise waits for drain. */
  waitForDrain(): Promise<void>
  /** Clean up listeners and timers. */
  destroy(): void
}

/**
 * Create a backpressure controller for a Socket.IO socket.
 *
 * Usage in an emit loop:
 *   const bp = createBackpressureController(socket, highWaterMark)
 *   for (const chunk of chunks) {
 *     socket.emit('data', chunk)
 *     await bp.waitForDrain()
 *   }
 *   bp.destroy()
 */
export function createBackpressureController(
  socket: BackpressureSocket,
  highWaterMark: number
): BackpressureController {
  let destroyed = false
  let pendingResolve: (() => void) | null = null
  let timerId: ReturnType<typeof setTimeout> | null = null

  const onDrain = (): void => {
    checkAndResolve()
  }

  const checkAndResolve = (): void => {
    if (pendingResolve === null) {
      return
    }
    const buffered = getWebSocketBufferedBytes(socket)
    const action = computeBackpressureAction(buffered, highWaterMark, true)
    if (action === 'resume' || buffered === null) {
      const resolve = pendingResolve
      pendingResolve = null
      clearTimer()
      socket.conn.removeListener('drain', onDrain)
      resolve()
    } else {
      // Re-schedule poll as safety net
      scheduleTimer()
    }
  }

  const scheduleTimer = (): void => {
    clearTimer()
    timerId = setTimeout(() => {
      timerId = null
      checkAndResolve()
    }, DRAIN_POLL_MS)
  }

  const clearTimer = (): void => {
    if (timerId !== null) {
      clearTimeout(timerId)
      timerId = null
    }
  }

  return {
    waitForDrain(): Promise<void> {
      if (destroyed) {
        return Promise.resolve()
      }
      const buffered = getWebSocketBufferedBytes(socket)
      const action = computeBackpressureAction(buffered, highWaterMark, false)
      if (action !== 'pause') {
        return Promise.resolve()
      }
      return new Promise<void>((resolve) => {
        pendingResolve = resolve
        socket.conn.once('drain', onDrain)
        scheduleTimer()
      })
    },
    destroy(): void {
      destroyed = true
      if (pendingResolve !== null) {
        const resolve = pendingResolve
        pendingResolve = null
        resolve()
      }
      clearTimer()
      socket.conn.removeListener('drain', onDrain)
    }
  }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npx vitest run tests/unit/backpressure.vitest.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add app/socket/backpressure.ts tests/unit/backpressure.vitest.ts
git commit -m "refactor: extract shared backpressure utilities from terminal adapter"
```

### Task 2: Update terminal adapter to use shared module

**Files:**

- Modify: `app/socket/adapters/service-socket-terminal.ts:18-85`
- Modify: `tests/unit/stream-backpressure.vitest.ts:9-10`

- [ ] **Step 1: Update terminal adapter imports**

In `app/socket/adapters/service-socket-terminal.ts`, remove the local `BackpressureState` interface, `LOW_WATER_MARK_DIVISOR` constant, `getWebSocketBufferedBytes` function, and `computeBackpressureAction` function (lines 18-85). Replace with imports from the shared module:

```typescript
import {
  getWebSocketBufferedBytes,
  computeBackpressureAction
} from '../backpressure.js'
```

Keep the `export` keywords on the re-exports so existing test imports don't break:

```typescript
export { getWebSocketBufferedBytes, computeBackpressureAction } from '../backpressure.js'
```

- [ ] **Step 2: Update existing test imports**

In `tests/unit/stream-backpressure.vitest.ts`, the existing imports on lines 9-10 import from the terminal adapter. These still work via re-exports, but add an additional test to verify the shared module directly. No changes needed if re-exports are in place.

- [ ] **Step 3: Run all existing tests**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npx vitest run tests/unit/stream-backpressure.vitest.ts tests/unit/backpressure.vitest.ts`
Expected: ALL PASS — existing terminal backpressure tests still pass, new shared tests pass

- [ ] **Step 4: Run typecheck**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run typecheck`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add app/socket/adapters/service-socket-terminal.ts tests/unit/stream-backpressure.vitest.ts
git commit -m "refactor: terminal adapter imports backpressure from shared module"
```

---

## Chunk 2: Switch SFTP Downloads to Binary Transfer

### Task 3: Update server-side SFTP to emit raw Buffer

**Files:**

- Modify: `app/services/sftp/sftp-service.ts:108-115,763-768`
- Modify: `app/socket/adapters/service-socket-sftp.ts:464-496`

- [ ] **Step 1: Change `DownloadChunkData.data` type from `string` to `Buffer`**

In `app/services/sftp/sftp-service.ts`, change the interface at line 113:

```typescript
// Before:
readonly data: string // Base64 encoded

// After:
readonly data: Buffer
```

- [ ] **Step 2: Remove base64 encoding in `emitBufferedChunks`**

In `app/services/sftp/sftp-service.ts`, replace lines 763-768:

```typescript
// Before:
          // Encode chunk as base64 and emit
          const base64Data = chunk.toString('base64')
          callbacks.onChunk({
            transferId,
            chunkIndex: nextChunkToEmit,
            data: base64Data,
            isLast
          })

// After:
          callbacks.onChunk({
            transferId,
            chunkIndex: nextChunkToEmit,
            data: chunk,
            isLast
          })
```

- [ ] **Step 3: Run typecheck to find any other references**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run typecheck`
Expected: Should pass — the `data` field is emitted over socket and not used as string server-side.

- [ ] **Step 4: Commit**

```bash
git add app/services/sftp/sftp-service.ts
git commit -m "feat: emit raw Buffer for SFTP download chunks instead of base64"
```

### Task 4: Update client-side to receive binary data

**Files:**

- Modify: `webssh2_client/client/src/types/sftp.ts:231-240`
- Modify: `webssh2_client/client/src/utils/download-assembler.ts:17-56,158-171`
- Modify: `webssh2_client/client/src/services/sftp-service.ts:363-391`

- [ ] **Step 1: Update `SftpDownloadChunkResponse` type**

In `webssh2_client/client/src/types/sftp.ts`, change lines 236-237:

```typescript
// Before:
  /** Base64 encoded binary data */
  readonly data: string

// After:
  /** Binary chunk data */
  readonly data: ArrayBuffer
```

- [ ] **Step 2: Update `ReceivedChunk` interface in download-assembler**

In `webssh2_client/client/src/utils/download-assembler.ts`, change lines 20-21:

```typescript
// Before:
  /** Base64 encoded data */
  readonly data: string

// After:
  /** Binary data */
  readonly data: ArrayBuffer | Uint8Array
```

- [ ] **Step 3: Remove `base64ToUint8Array` and update `addChunk`**

In `webssh2_client/client/src/utils/download-assembler.ts`:

Remove the `base64ToUint8Array` function (lines 49-56).

Update `addChunk` (around line 169) to use binary data directly:

```typescript
// Before:
    const data = base64ToUint8Array(chunk.data)

// After:
    const data = chunk.data instanceof Uint8Array
      ? chunk.data
      : new Uint8Array(chunk.data)
```

Update the module docstring (lines 4-5):

```typescript
// Before:
 * Assembles received chunks into a Blob and triggers browser download.
 * Handles base64 decoding and chunk ordering.

// After:
 * Assembles received chunks into a Blob and triggers browser download.
 * Handles binary chunk ordering and assembly.
```

- [ ] **Step 4: Update client sftp-service handleDownloadChunk**

In `webssh2_client/client/src/services/sftp-service.ts`, the `handleDownloadChunk` function passes `response.data` to the assembler. No code change needed here since it already passes `data: response.data` — the type change propagates automatically.

- [ ] **Step 5: Run client typecheck**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2_client && npm run typecheck 2>&1 || true`
Expected: PASS (or identify any remaining string references to fix)

- [ ] **Step 6: Run client tests**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2_client && npm run test 2>&1 || true`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
cd /Users/bill/Documents/GitHub/webssh/webssh2_client
git add client/src/types/sftp.ts client/src/utils/download-assembler.ts client/src/services/sftp-service.ts
git commit -m "feat: receive binary SFTP download chunks instead of base64"
```

---

## Chunk 3: Add Backpressure to SFTP Downloads

### Task 5: Make SFTP download callbacks async and add backpressure

**Files:**

- Modify: `app/services/sftp/sftp-service.ts:120-122,751-805`
- Modify: `app/socket/adapters/service-socket-sftp.ts:464-496`

- [ ] **Step 1: Write a test for backpressure-aware chunk emission**

Add a test file `tests/unit/sftp-download-backpressure.vitest.ts`:

```typescript
// tests/unit/sftp-download-backpressure.vitest.ts
import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  createBackpressureController,
  type BackpressureSocket
} from '../../app/socket/backpressure.js'

describe('SFTP Download Backpressure', () => {
  it('controller resolves immediately when buffer is low', async () => {
    const socket = makeMockSocket(100)
    const controller = createBackpressureController(socket, 16384)

    const start = Date.now()
    await controller.waitForDrain()
    const elapsed = Date.now() - start

    expect(elapsed).toBeLessThan(50)
    controller.destroy()
  })

  it('controller blocks when buffer is high and resumes on drain', async () => {
    let buffered = 20000
    const listeners = new Map<string, () => void>()
    const socket = {
      conn: {
        transport: {
          name: 'websocket',
          socket: { get bufferedAmount() { return buffered } }
        },
        once: vi.fn((event: string, cb: () => void) => {
          listeners.set(event, cb)
        }),
        removeListener: vi.fn()
      } as never
    } as BackpressureSocket

    const controller = createBackpressureController(socket, 16384)

    let resolved = false
    const drainPromise = controller.waitForDrain().then(() => {
      resolved = true
    })

    // Not yet resolved
    await Promise.resolve()
    expect(resolved).toBe(false)

    // Simulate drain
    buffered = 1000
    const drainCb = listeners.get('drain')
    if (drainCb) drainCb()

    await drainPromise
    expect(resolved).toBe(true)
    controller.destroy()
  })

  it('controller destroy resolves pending waitForDrain', async () => {
    const socket = makeMockSocket(20000)
    const controller = createBackpressureController(socket, 16384)

    let resolved = false
    const promise = controller.waitForDrain().then(() => { resolved = true })

    controller.destroy()
    await promise
    expect(resolved).toBe(true)
  })
})

function makeMockSocket(bufferedAmount: number): BackpressureSocket {
  return {
    conn: {
      transport: {
        name: 'websocket',
        socket: { bufferedAmount }
      },
      once: vi.fn(),
      removeListener: vi.fn()
    } as never
  } as BackpressureSocket
}
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npx vitest run tests/unit/sftp-download-backpressure.vitest.ts`
Expected: PASS (these test the already-implemented controller from Task 1)

- [ ] **Step 3: Make `DownloadStreamCallbacks.onChunk` return a Promise**

In `app/services/sftp/sftp-service.ts`, update the callback interface around line 122:

```typescript
// Before:
  onChunk: (chunk: DownloadChunkData) => void

// After:
  onChunk: (chunk: DownloadChunkData) => void | Promise<void>
```

- [ ] **Step 4: Await `onChunk` in `emitBufferedChunks` and make it async**

In `app/services/sftp/sftp-service.ts`, the `emitBufferedChunks` function (starting around line 751) needs to become async and await `onChunk`. The critical change is:

```typescript
// Before (line 751):
      const emitBufferedChunks = (): void => {

// After:
      const emitBufferedChunks = async (): Promise<void> => {
```

And inside the while loop, after calling `callbacks.onChunk(...)`, await it:

```typescript
// Before:
          callbacks.onChunk({
            transferId,
            chunkIndex: nextChunkToEmit,
            data: chunk,
            isLast
          })

// After:
          await callbacks.onChunk({
            transferId,
            chunkIndex: nextChunkToEmit,
            data: chunk,
            isLast
          })
```

Also update the call site in `readChunk` (around line 848) since `emitBufferedChunks` is now async:

```typescript
// Before:
            emitBufferedChunks()

// After:
            void emitBufferedChunks()
```

Note: We use `void` (fire-and-forget) in the SFTP read callback because the read callback is synchronous. The backpressure pause happens *inside* `emitBufferedChunks` — when it awaits `onChunk`, no new chunks are emitted until the drain completes, which naturally throttles how fast data flows to the socket.

- [ ] **Step 5: Add backpressure controller to the SFTP adapter**

In `app/socket/adapters/service-socket-sftp.ts`, update the download handler (lines 464-496). Add import at top of file:

```typescript
import {
  createBackpressureController
} from '../backpressure.js'
```

Update `STREAM_LIMITS` import:

```typescript
import { STREAM_LIMITS } from '../../constants/core.js'
```

Replace the download callbacks section:

```typescript
      // Before (lines 464-496):
      const downloadCallbacks: DownloadStreamCallbacks = {
        onChunk: (chunk) => {
          this.context.socket.emit(SOCKET_EVENTS.SFTP_DOWNLOAD_CHUNK, chunk)
        },
        ...
      }

      // After:
      const highWaterMark = STREAM_LIMITS.SOCKET_HIGH_WATER_MARK
      const bpController = createBackpressureController(
        this.context.socket as never,
        highWaterMark
      )

      const downloadCallbacks: DownloadStreamCallbacks = {
        onChunk: async (chunk) => {
          this.context.socket.emit(SOCKET_EVENTS.SFTP_DOWNLOAD_CHUNK, chunk)
          await bpController.waitForDrain()
        },
        onProgress: (progress) => {
          this.context.socket.emit(SOCKET_EVENTS.SFTP_PROGRESS, progress)
        },
        onComplete: (complete) => {
          bpController.destroy()
          this.context.socket.emit(SOCKET_EVENTS.SFTP_COMPLETE, complete)
          this.logSftpOperation('download_complete', 'success', complete.durationMs, {
            transferId,
            bytesTransferred: complete.bytesTransferred
          })
        },
        onError: (error) => {
          bpController.destroy()
          this.emitSftpError('download', error)
          this.logSftpOperation('download_chunk', 'failure', 0, {
            transferId,
            error: error.code
          })
        }
      }
```

- [ ] **Step 6: Run typecheck**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run typecheck`
Expected: PASS

- [ ] **Step 7: Run all tests**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npx vitest run`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add app/services/sftp/sftp-service.ts app/socket/adapters/service-socket-sftp.ts tests/unit/sftp-download-backpressure.vitest.ts
git commit -m "feat: add backpressure control to SFTP download streaming

Fixes large file downloads (300MB+) causing 'ping timeout' disconnects
by throttling chunk emission when the WebSocket send buffer is full.

Resolves #492"
```

---

## Chunk 4: Build Verification & Cleanup

### Task 6: Full build and lint verification

**Files:**

- All modified files

- [ ] **Step 1: Run server lint**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run lint`
Expected: 0 warnings, 0 errors

- [ ] **Step 2: Run server typecheck**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run typecheck`
Expected: PASS

- [ ] **Step 3: Run all server tests**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run test`
Expected: ALL PASS

- [ ] **Step 4: Run server build**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2 && npm run build`
Expected: PASS

- [ ] **Step 5: Run client typecheck and build**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2_client && npm run typecheck && npm run build`
Expected: PASS

- [ ] **Step 6: Run client tests**

Run: `cd /Users/bill/Documents/GitHub/webssh/webssh2_client && npm run test`
Expected: PASS

- [ ] **Step 7: Fix any issues found and commit**

If any issues are found in steps 1-6, fix them and create a new commit.

---

## Summary of Changes

| Change | Impact |
| --- | --- |
| Extract backpressure to shared module | Enables reuse, no behavior change |
| Remove base64 encode/decode | 33% less data over wire, zero encode/decode CPU |
| Add `BackpressureController` | Pauses chunk emission when WebSocket buffer is full |
| Async `onChunk` callback | Allows SFTP service to yield to backpressure |
| `bpController.destroy()` on complete/error | Clean up listeners and timers |

**Expected outcome:** SFTP downloads of any size (up to `maxFileSize`) complete without ping timeout disconnections. The WebSocket send buffer stays bounded, allowing Socket.IO ping/pong heartbeats to flow normally.
