// ============================================================================
// Deno Serverless VLESS-over-WebSocket Edge Gateway (Hardened v2.1.4-resilient)
// Guaranteed Stream Integrity & Zero-Loss Chunk Queuing
// ============================================================================

interface VlessHeader {
  version: number;
  uuidMatches: boolean;
  command: number;
  port: number;
  address: string;
  payload: Uint8Array;
}

// ----------------------------------------------------------------------------
// Runtime Configuration
// ----------------------------------------------------------------------------
const USER_UUID = Deno.env.get("UUID") || "b2f903d7-1108-4c1c-8817-788faa6e181a";
const AUTH_PATH = Deno.env.get("AUTH_PATH") || "/api";
const PORT = Number(Deno.env.get("PORT")) || 8000;

// Надежный тайм-аут бездействия: 180 секунд (3 минуты).
// Покрывает любые длительные фазы глубокого мышления моделей (Thinking/CoT) до 3 минут без обрывов сокетов.
const IDLE_TIMEOUT_MS = 180_000;

function uuidToBytes(uuidStr: string): Uint8Array {
  const clean = uuidStr.replace(/-/g, "").toLowerCase();
  if (clean.length !== 32) throw new Error("UUID must be 32 hex chars");
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

const EXPECTED_UUID = uuidToBytes(USER_UUID);

function parseVlessHeader(buffer: Uint8Array): VlessHeader | null {
  if (buffer.length < 24) return null;

  const version = buffer[0];
  const clientUuid = buffer.subarray(1, 17);

  let uuidMatches = true;
  for (let i = 0; i < 16; i++) {
    if (clientUuid[i] !== EXPECTED_UUID[i]) {
      uuidMatches = false;
      break;
    }
  }

  const addonLength = buffer[17];
  let offset = 18 + addonLength;

  if (buffer.length < offset + 4) return null;

  const command = buffer[offset]; // 1 = TCP (CONNECT)
  offset += 1;

  const port = (buffer[offset] << 8) | buffer[offset + 1];
  offset += 2;

  const addressType = buffer[offset];
  offset += 1;

  let address = "";
  if (addressType === 1) {
    if (buffer.length < offset + 4) return null;
    address = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
    offset += 4;
  } else if (addressType === 2) {
    if (buffer.length < offset + 1) return null;
    const domainLength = buffer[offset];
    offset += 1;
    if (buffer.length < offset + domainLength) return null;
    address = new TextDecoder().decode(buffer.subarray(offset, offset + domainLength));
    offset += domainLength;
  } else if (addressType === 3) {
    if (buffer.length < offset + 16) return null;
    const parts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buffer[offset + i] << 8) | buffer[offset + i + 1]).toString(16));
    }
    address = parts.join(":");
    offset += 16;
  } else {
    return null;
  }

  const payload = buffer.subarray(offset);
  return { version, uuidMatches, command, port, address, payload };
}

// Гарантированная полная запись буфера в TCP-сокет без усечения
async function writeAll(conn: Deno.TcpConn, data: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < data.length) {
    const written = await conn.write(data.subarray(offset));
    if (written === null || written === 0) {
      throw new Error("TCP connection closed during write");
    }
    offset += written;
  }
}

Deno.serve({ port: PORT }, (req: Request) => {
  const url = new URL(req.url);

  // Healthcheck для мониторинга
  if (req.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return new Response(
      JSON.stringify({
        status: "operational",
        service: "edge-gateway-hardened",
        version: "2.1.4-resilient",
        idleTimeoutMs: IDLE_TIMEOUT_MS,
        timestamp: new Date().toISOString(),
      }),
      {
        status: 200,
        headers: { "content-type": "application/json; charset=utf-8" },
      }
    );
  }

  // Проверка пути аутентификации
  if (url.pathname !== AUTH_PATH && url.pathname !== "/") {
    return new Response("Unauthorized", { status: 401 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);
  let tcpConn: Deno.TcpConn | null = null;
  let isHandshakeStarted = false;
  let isClosed = false;
  let idleTimer: ReturnType<typeof setTimeout> | null = null;

  // Очереди для предотвращения гонок и рассинхронизации байтов
  const pendingBuffer: Uint8Array[] = [];
  let writeChain: Promise<void> = Promise.resolve();

  function resetIdleTimer() {
    if (isClosed) return;
    if (idleTimer !== null) {
      clearTimeout(idleTimer);
    }
    idleTimer = setTimeout(() => {
      safeClose(1000, "Inactivity timeout");
    }, IDLE_TIMEOUT_MS);
  }

  function safeClose(code = 1000, reason = "Normal Closure") {
    if (isClosed) return;
    isClosed = true;

    // 1. Остановка таймера бездействия
    if (idleTimer !== null) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }

    // 2. Мгновенная очистка очереди буферов
    pendingBuffer.length = 0;

    // 3. Закрытие WebSocket со стандартным RFC кодом 1000 (нормальное закрытие)
    try {
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close(code, reason);
      }
    } catch (_) {}

    // 4. Закрытие TCP-сокета и очистка ссылки для сборщика мусора V8
    if (tcpConn) {
      try { tcpConn.close(); } catch (_) {}
      tcpConn = null;
    }
  }

  // Последовательная отправка в сокет без перемешивания данных
  function enqueueWrite(data: Uint8Array) {
    if (isClosed || !tcpConn) return;
    writeChain = writeChain
      .then(() => writeAll(tcpConn!, data))
      .catch((_) => safeClose(1011, "Write Failed"));
  }

  socket.binaryType = "arraybuffer";

  // Запуск таймера бездействия при установке соединения
  resetIdleTimer();

  socket.onmessage = async (e: MessageEvent) => {
    if (isClosed) return;
    try {
      resetIdleTimer();
      const data = new Uint8Array(e.data as ArrayBuffer);

      if (!isHandshakeStarted) {
        isHandshakeStarted = true;

        const parsed = parseVlessHeader(data);
        if (!parsed || !parsed.uuidMatches || parsed.command !== 1) {
          safeClose(1008, "Policy Violation");
          return;
        }

        try {
          tcpConn = await Deno.connect({ hostname: parsed.address, port: parsed.port });
        } catch (_) {
          safeClose(1011, "Target Connect Failed");
          return;
        }

        // Подтверждение клиенту (VLESS response: 0x00 0x00)
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(new Uint8Array([0, 0]));
        }

        // Запись полезного груза из первого пакета
        if (parsed.payload && parsed.payload.length > 0) {
          enqueueWrite(parsed.payload);
        }

        // Запись всех пакетов, накопившихся во время установки TCP-соединения
        while (pendingBuffer.length > 0) {
          const chunk = pendingBuffer.shift()!;
          enqueueWrite(chunk);
        }

        // Потоковое чтение из TCP обратно в WebSocket с переиспользуемым 32КБ буфером
        (async () => {
          const buf = new Uint8Array(32768);
          try {
            while (!isClosed && tcpConn) {
              const n = await tcpConn.read(buf);
              if (n === null) break;
              resetIdleTimer();
              if (socket.readyState === WebSocket.OPEN) {
                socket.send(buf.subarray(0, n));
              } else {
                break;
              }
            }
          } catch (_) {
          } finally {
            safeClose(1000, "Upstream Closed");
          }
        })();
      } else if (tcpConn === null) {
        // Рукопожатие Deno.connect еще идет: буферизуем входящие пакеты
        pendingBuffer.push(data);
      } else {
        // Соединение активно: отправляем строго через сериализованную очередь writeAll
        enqueueWrite(data);
      }
    } catch (_) {
      safeClose(1011, "Message Error");
    }
  };

  socket.onclose = () => safeClose(1000, "Client Closed");
  socket.onerror = () => safeClose(1006, "WebSocket Error");

  return response;
});
