export function missionFromRow(row) {
  const body = row.body && typeof row.body === 'object' ? { ...row.body } : {};
  const createdAt =
    body.createdAt ||
    (row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at);
  const updatedAt =
    body.updatedAt ||
    (row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at);
  return {
    ...body,
    id: row.id,
    status: row.status,
    assignedTo: row.assigned_to != null ? String(row.assigned_to) : null,
    createdBy: row.created_by != null ? String(row.created_by) : null,
    createdAt,
    updatedAt,
  };
}

export function userPublicFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    phone: row.phone,
    photoURL: row.photo_url,
    distanceDisplayMode: row.distance_display_mode,
    language: row.language,
    points: row.points ?? 0,
    fcmToken: row.fcm_token,
    dateOfJoining:
      row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

export function clientFromRow(row) {
  const body = row.body && typeof row.body === 'object' ? { ...row.body } : {};
  return {
    ...body,
    id: row.id,
    phone: row.phone || body.phone,
    createdAt: body.createdAt || row.created_at,
    updatedAt: body.updatedAt || row.updated_at,
  };
}

export function restaurantFromRow(row) {
  const body = row.body && typeof row.body === 'object' ? { ...row.body } : {};
  return {
    ...body,
    id: row.id,
    createdAt: body.createdAt || row.created_at,
    updatedAt: body.updatedAt || row.updated_at,
  };
}
