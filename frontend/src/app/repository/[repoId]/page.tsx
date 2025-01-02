"use client";

import { useParams } from "next/navigation";

import { RepositoryView } from "@/components/views";

export default function RepositoryPage() {
  const { repoId } = useParams();

  return <RepositoryView repoId={repoId as string} />;
}
