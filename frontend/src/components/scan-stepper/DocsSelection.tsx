"use client";
import { type FC, useCallback, useEffect, useMemo } from "react";

import {
  Input,
  Table,
  TableHeader,
  TableColumn,
  TableBody,
  TableRow,
  TableCell,
  Spinner,
  Accordion,
  AccordionItem,
  type Selection,
} from "@nextui-org/react";
import { Sparkles } from "lucide-react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import { BottomBanner } from "@/components/layout";
import { PRO_PLAN_DETAILS } from "@/config/constants";
import { HELP_DESCRIPTION } from "@/config/helpDescription";
import { useAuth } from "@/contexts/AuthContext";
import { useScanStepper } from "@/hooks";
import { useScanStepperStore } from "@/store/scanStepperStore";

import { HelpGuide } from "./HelpGuide";
import { QnABox } from "./QnABox";

export const DocsSelection: FC = () => {
  const {
    readmeFiles,
    repoDocs,
    contractSearch,
    setContractSearch,
    setRepoDocs,
    selectedOwner,
    selectedRepo,
    selectedBranch,
    isLoading,
    isFileLimitExceeded,
  } = useScanStepperStore();

  const { user } = useAuth();
  const router = useRouter();
  const { fetchReadmeFiles, fetchPreviousDocs } = useScanStepper();

  const filteredReadmeFiles = useMemo(() => {
    const searchLower = contractSearch.toLowerCase();
    return readmeFiles.filter((file) => file.path.toLowerCase().includes(searchLower));
  }, [readmeFiles, contractSearch]);

  const calculateTotalSelectedChars = useCallback(() => {
    const fileMap = new Map(readmeFiles.map((file) => [file.path, file.character_count]));
    return repoDocs.readme.reduce((acc, path) => {
      return acc + (fileMap.get(path) || 0);
    }, 0);
  }, [readmeFiles, repoDocs]);

  const totalSelectedChars = calculateTotalSelectedChars();

  const allPaths = useMemo(() => filteredReadmeFiles.map((file) => file.path), [filteredReadmeFiles]);

  const handleSelectionChange = useCallback(
    (selection: Selection) => {
      if (selection === "all") {
        setRepoDocs({ readme: allPaths });
      } else {
        setRepoDocs({ readme: Array.from(selection).map(String) });
      }
    },
    [allPaths, setRepoDocs],
  );

  // Fetch previous docs if user is a subscriber
  useEffect(() => {
    if (user?.subscription.isActive && selectedOwner && selectedRepo) {
      fetchPreviousDocs(selectedOwner.login, selectedRepo.name);
    }
  }, [selectedOwner, selectedRepo, user?.subscription.isActive, fetchPreviousDocs]);

  // Fetch readme files when owner/repo/branch changes
  useEffect(() => {
    if (selectedOwner && selectedRepo && selectedBranch) {
      fetchReadmeFiles(selectedOwner, selectedRepo, selectedBranch);
    }
  }, [fetchReadmeFiles, selectedOwner, selectedRepo, selectedBranch]);

  const isBlurred = !user?.subscription.isActive;

  return (
    <div className="h-full w-full flex flex-col">
      <section
        className={`flex-1 min-h-0 overflow-auto flex justify-center ${isBlurred ? "blur-sm select-none cursor-default" : ""}`}
      >
        <div className="w-3/4">
          <Accordion selectionMode="multiple">
            <AccordionItem
              classNames={{
                title: "text-base font-normal text-default-600 font-inter leading-6",
              }}
              key="1"
              aria-label="Select Readme files (Optional)"
              title="Select Readme files (Optional)"
            >
              <div className="flex gap-8">
                <div className="flex-1 max-w-[70%]">
                  <h3 className="text-sm font-normal mb-2 text-default-600 font-inter leading-6"> Readme files </h3>
                  <div className="overflow-auto">
                    <Table
                      isHeaderSticky
                      aria-label="Readme files table"
                      selectionMode={user?.subscription.isActive ? "multiple" : "none"}
                      color="secondary"
                      onSelectionChange={handleSelectionChange}
                      selectedKeys={repoDocs.readme}
                      disabledKeys={
                        isFileLimitExceeded
                          ? readmeFiles.filter((file) => !repoDocs.readme.includes(file.path)).map((file) => file.path)
                          : []
                      }
                      classNames={{
                        base: "max-w-full max-h-80 gap-0 border-2 border-default-100 rounded-xl overflow-hidden",
                        table: "min-w-full",
                        th: "bg-background",
                        wrapper: "rounded-none",
                      }}
                      topContent={
                        <Input
                          classNames={{
                            base: "border-b-2 border-default-100",
                            inputWrapper: "bg-content-1",
                          }}
                          radius="none"
                          aria-label="Search files"
                          isClearable={true}
                          placeholder="Search files..."
                          value={contractSearch}
                          onChange={(e) => setContractSearch(e.target.value)}
                          onClear={() => setContractSearch("")}
                          startContent={<Image src="/svg/search.svg" alt="Search" width={16} height={16} />}
                        />
                      }
                      topContentPlacement="outside"
                    >
                      <TableHeader className="rounded-none">
                        <TableColumn>Path</TableColumn>
                        <TableColumn>Char</TableColumn>
                      </TableHeader>
                      <TableBody
                        isLoading={!!isLoading}
                        loadingContent={<Spinner />}
                        emptyContent={
                          <div className="flex flex-col items-center">
                            <Image
                              src="/svg/empty_contract.svg"
                              alt="No Readme files found"
                              width={100}
                              height={100}
                              className="mt-8"
                            />
                            <p className="mt-2 text-gray-500">No Readme files found</p>
                          </div>
                        }
                      >
                        {readmeFiles.map((file) => (
                          <TableRow key={file.path}>
                            <TableCell>{file.path}</TableCell>
                            <TableCell>{file.character_count}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
                <div className="w-[30%]">
                  <HelpGuide
                    selectedLines={totalSelectedChars}
                    totalLines={PRO_PLAN_DETAILS.MAX_DOCS_CHARS}
                    selectedFiles={repoDocs.readme.length}
                    totalFiles={PRO_PLAN_DETAILS.MAX_DOCS_FILES}
                    description={HELP_DESCRIPTION.readme}
                    variant="readme"
                  />
                </div>
              </div>
            </AccordionItem>

            <AccordionItem
              classNames={{ title: "text-base font-normal text-default-600 font-inter leading-6" }}
              key="2"
              aria-label="Additional Q&A (Optional)"
              title="Additional Q&A (Optional)"
            >
              <QnABox />
            </AccordionItem>
          </Accordion>
        </div>
      </section>

      {!user?.subscription.isActive && (
        <BottomBanner
          title="Context docs are for subscribers only"
          description="Please subscribe to access the docs and Q&A."
          buttonText="Subscribe Now"
          buttonIcon={<Sparkles size={14} />}
          action={() => router.push("/profile?tab=subscription")}
        />
      )}
    </div>
  );
};
