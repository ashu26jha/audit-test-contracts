import axios, { AxiosError } from "axios";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

import { SERVICES } from "@/config/constants";

const apiKey = process.env.X_API_KEY;

export async function GET(request: NextRequest) {
  const scanId = request.nextUrl.searchParams.get("scanId");
  const cookieStore = cookies();
  const token = cookieStore.get("auth_token")?.value;

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

    const response = await axios.get(`/api/v1/scans/result/${scanId}`, {
      baseURL,
      headers: {
        Cookie: `auth_token=${token}`,
        "Content-Type": "application/json",
        "x-api-key": apiKey,
      },
    });

    const result = response.data.data.result;
    const scan = response.data.data.scan;
    result.scan = scan;

    // Sort the findings by severity
    const severityOrder = ["Critical", "High", "Medium", "Low", "Info", "Best Practices"];
    result.findings.sort((a: Finding, b: Finding) => {
      return severityOrder.indexOf(a.Severity) - severityOrder.indexOf(b.Severity);
    });

    return NextResponse.json(result);
  } catch (error) {
    const axiosError = error as AxiosError;
    const message = axiosError.message ?? axiosError.response?.statusText ?? error;
    console.error("Error fetching full scan results:", message);

    if (axios.isAxiosError(error)) {
      const status = axiosError.response?.status || 500;
      return NextResponse.json({ error: message }, { status });
    }
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
