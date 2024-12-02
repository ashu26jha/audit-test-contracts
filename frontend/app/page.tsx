"use client";

import { Loading } from "@/components/Loading";

import { useAuth } from "../contexts/AuthContext";

export default function Home() {
  const { loading } = useAuth();

  if (loading) {
    return <Loading />;
  }

  return null;
}
