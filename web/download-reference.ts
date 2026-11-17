// Preserve legacy owner checkpoints; received files bind every request and cache to one grant.
export function downloadReference(file: { id: string; deliveryId?: string }) {
  return file.deliveryId ? `${file.id}:delivery:${file.deliveryId}` : file.id;
}
export function downloadAccess(file: { id: string; deliveryId?: string }) {
  return { fileId: file.id, ...(file.deliveryId ? { deliveryId: file.deliveryId } : {}) };
}
