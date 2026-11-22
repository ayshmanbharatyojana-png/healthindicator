
export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(
      "SELECT status FROM system_health ORDER BY id DESC LIMIT 1"
    ).first();

    return Response.json({
      success: true,
      database_connected: true,
      message: "Ayodhya Health Database Connected",
      database_status: result
    });
  } catch (error) {
    return Response.json({
      success: false,
      database_connected: false,
      message: "Database connection failed"
    }, { status: 500 });
  }
}

