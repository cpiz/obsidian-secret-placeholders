import { t } from "../../i18n";
import { BitwardenApiError, type BitwardenClient, type DeviceApproval } from "./client";

// Leave a short margin before Vaultwarden's five-minute token exchange deadline.
const APPROVAL_TIMEOUT_MS = 4 * 60_000 + 45_000;
const POLL_INTERVAL_MS = 5_000;

export async function waitForDeviceApproval(
  client: BitwardenClient,
  email: string,
  publicKey: string,
  accessCode: string,
  signal: AbortSignal,
  onRequested: () => void,
): Promise<{ requestId: string; encryptedKey: string; legacy: boolean }> {
  const controller = new AbortController();
  const cancel = () => controller.abort(signal.reason);
  signal.addEventListener("abort", cancel, { once: true });
  if (signal.aborted) cancel();
  const timeout = window.setTimeout(
    () => controller.abort(new Error(t("provider.bitwarden.deviceLoginTimeout"))),
    APPROVAL_TIMEOUT_MS,
  );
  const pending = controller.signal;
  const aborted = new Promise<never>((_, reject) => {
    const fail = () => reject(pending.reason instanceof Error
      ? pending.reason
      : new Error("Device approval cancelled"));
    if (pending.aborted) fail();
    else pending.addEventListener("abort", fail, { once: true });
  });

  const poll = async () => {
    pending.throwIfAborted();
    let requestId: string;
    try {
      requestId = await client.createDeviceApproval(email, publicKey, accessCode);
    } catch {
      throw new Error(t("provider.bitwarden.deviceLoginRequestFailed"));
    }
    pending.throwIfAborted();
    onRequested();

    while (!pending.aborted) {
      let approval: DeviceApproval | undefined;
      try {
        approval = await client.getDeviceApproval(requestId, accessCode);
      } catch (e) {
        // Transport errors may include the request URL with the access code.
        if (!(e instanceof BitwardenApiError && e.status === 429)) {
          throw new Error(t("provider.bitwarden.deviceLoginEnded"));
        }
      }
      pending.throwIfAborted();
      if (approval?.approved === false) {
        throw new Error(t("provider.bitwarden.deviceLoginEnded"));
      }
      if (approval?.approved) {
        if (!approval.encryptedKey) throw new Error(t("provider.bitwarden.deviceLoginKeyFailed"));
        return {
          requestId,
          encryptedKey: approval.encryptedKey,
          legacy: Boolean(approval.encryptedMasterPasswordHash),
        };
      }
      const interval = approval ? POLL_INTERVAL_MS : POLL_INTERVAL_MS * 2;
      await new Promise<void>((resolve) => window.setTimeout(resolve, interval));
    }
    throw pending.reason;
  };

  try {
    return await Promise.race([poll(), aborted]);
  } finally {
    window.clearTimeout(timeout);
    signal.removeEventListener("abort", cancel);
    controller.abort();
  }
}
