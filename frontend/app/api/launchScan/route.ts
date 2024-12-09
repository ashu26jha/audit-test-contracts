import axios, { AxiosError } from "axios";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { SERVICES } from "@/config/constants";

const apiKey = process.env.X_API_KEY;

export async function POST(request: NextRequest) {
  const cookieStore = cookies();
  const token = cookieStore.get("auth_token")?.value;

  if (!token) {
    return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  }

  if (!apiKey) {
    return NextResponse.json({ error: "API key is not configured" }, { status: 500 });
  }

  try {
    const body = await request.json();
    const baseURL = process.env.DOCKER_ENV === "true" ? "http://backend:8000" : SERVICES.API_URL;

    const response = await axios.post(`/api/v1/audit-agent`, body, {
      baseURL,
      headers: {
        Cookie: `auth_token=${token}`,
        "Content-Type": "application/json",
        "x-api-key": apiKey,
      },
    });

    return NextResponse.json(response.data);
  } catch (error) {
    const axiosError = error as AxiosError;
    const message = axiosError.message ?? axiosError.response?.statusText ?? error;
    console.error("Error launching scan:", message);

    if (axios.isAxiosError(error)) {
      const status = axiosError.response?.status || 500;
      return NextResponse.json({ error: message }, { status });
    }
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
