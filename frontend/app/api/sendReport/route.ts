import axios, { AxiosError } from "axios";
import { NextRequest, NextResponse } from "next/server";

import { SERVICES } from "@/config/constants";

const apiKey = process.env.X_API_KEY;

export async function GET(request: NextRequest) {
  const scanId = request.nextUrl.searchParams.get("scanId");
  const authHeader = request.headers.get("Authorization");
  const token = authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : null;

  if (!scanId) {
    return NextResponse.json({ error: "Scan ID is required" }, { status: 400 });
  }

  if (!token) {
    return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  }

  if (!apiKey) {
    return NextResponse.json({ error: "API key is not configured" }, { status: 500 });
  }

  try {
    const baseURL = process.env.DOCKER_ENV === "true" ? "http://backend:8000" : SERVICES.API_URL;

    const response = await axios.get(`/api/v1/generate-pdf/${scanId}`, {
      baseURL,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "x-api-key": apiKey,
      },
    });
    return NextResponse.json(response.data);
  } catch (error) {
    const axiosError = error as AxiosError;
    const message = axiosError.message ?? axiosError.response?.statusText ?? error;
    console.error("Error generating PDF:", message);

    if (axios.isAxiosError(error) && error.response?.status === 429) {
      return NextResponse.json(
        {
          success: false,
          message: "Rate limit exceeded. Please try again later.",
        },
        { status: 429 },
      );
    }
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
