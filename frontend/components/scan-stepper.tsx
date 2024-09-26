import React, { useState, useEffect } from "react";
import {
  Button,
  Table,
  TableHeader,
  TableColumn,
  TableBody,
  TableRow,
  TableCell,
  Select,
  SelectItem,
  Spinner,
  Card,
  CardHeader,
  Input,
} from "@nextui-org/react";
import { Autocomplete, AutocompleteItem } from "@nextui-org/autocomplete";
import { useRouter } from "next/navigation";
import { useAuth } from "../contexts/AuthContext";
import { ArrowRight } from "lucide-react";
import {
  getOrganizationsAndPersonal,
  getRepositories,
  getRepositoryContents,
  getBranches,
  initiateScan,
} from "../services/api";
import Image from "next/image";

interface Owner {
  login: string;
  type: "user" | "organization";
}

interface Repository {
  name: string;
  updatedAt: string;
}

interface File {
  name: string;
  path: string;
  type: string;
  download_url: string;
}

const steps = [
  {
    notSelectedIcon: <Image src="/repository.svg" alt="Repository" width={45} height={45} />,
    selectingIcon: <Image src="/repository_selecting.svg" alt="Repository Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/repository_selected.svg" alt="Repository Selected" width={100} height={100} />,
    label: "Repository",
  },
  {
    notSelectedIcon: <Image src="/branch.svg" alt="Branch" width={45} height={45} />,
    selectingIcon: <Image src="/branch_selecting.svg" alt="Branch Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/branch_selected.svg" alt="Branch Selected" width={60} height={60} />,
    label: "Branch",
  },
  {
    notSelectedIcon: <Image src="/contract.svg" alt="Contract" width={45} height={45} />,
    selectingIcon: <Image src="/contract_selecting.svg" alt="Contract Selecting" width={45} height={45} />,
    selectedIcon: <Image src="/contract_selected.svg" alt="Contract Selected" width={60} height={60} />,
    label: "Contract",
  },
];

const ScanStepper: React.FC = () => {
  const router = useRouter();
  const [currentStep, setCurrentStep] = useState(1);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [selectedBranch, setSelectedBranch] = useState("");
  const [selectedContracts, setSelectedContracts] = useState<string[]>([]);
  const [isNextEnabled, setIsNextEnabled] = useState(false);
  const [contractSearch, setContractSearch] = useState("");

  const { token } = useAuth();
  const [owners, setOwners] = useState<Owner[]>([]);
  const [selectedOwner, setSelectedOwner] = useState<Owner | null>(null);
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [branches, setBranches] = useState<string[]>([]);
  const [solidityFiles, setSolidityFiles] = useState<File[]>([]);

  const filteredSolidityFiles = solidityFiles.filter(
    (file) =>
      file.name.toLowerCase().includes(contractSearch.toLowerCase()) ||
      file.path.toLowerCase().includes(contractSearch.toLowerCase()),
  );

  useEffect(() => {
    setIsNextEnabled(
      (currentStep === 1 && selectedOwner !== null && selectedRepo !== null) ||
        (currentStep === 2 && selectedBranch !== "") ||
        (currentStep === 3 && selectedContracts.length > 0),
    );
  }, [currentStep, selectedOwner, selectedOrg, selectedRepo, selectedBranch, selectedContracts]);

  const handleScan = async () => {
    if (currentStep === steps.length) {
      setIsLoading(true);
      try {
        if (token) {
          const response = await initiateScan(token, {
            repositoryURL: `https://github.com/${selectedOwner?.login}/${selectedRepo?.name}`,
            contractFiles: selectedContracts,
            branchName: selectedBranch,
          });

          console.log("Scan initiated:", response);
          router.push(`/scan-results/${response.data.scan_id}`);
        }
      } catch (error) {
        console.error("Error initiating scan:", error);
      } finally {
        setIsLoading(false);
      }
    } else {
      handleNext();
    }
  };

  const handleNext = () => {
    if (currentStep < steps.length) {
      setCurrentStep(currentStep + 1);
    } else {
      setIsLoading(true);
      setTimeout(() => {
        setIsLoading(false);
        console.log("Scan completed for contracts:", selectedContracts);
        router.push("/scan-results");
      }, 3000);
    }
  };

  useEffect(() => {
    if (token) {
      getOrganizationsAndPersonal(token).then(setOwners).catch(console.error);
    }
  }, [token]);

  useEffect(() => {
    if (token && selectedOwner) {
      getRepositories(token, selectedOwner.login, selectedOwner.type).then(setRepositories).catch(console.error);
    }
  }, [token, selectedOwner]);

  useEffect(() => {
    if (token && selectedOwner && selectedRepo) {
      getBranches(token, selectedOwner.login, selectedRepo.name).then(setBranches).catch(console.error);
    }
  }, [token, selectedOwner, selectedRepo]);

  useEffect(() => {
    if (token && selectedOwner && selectedRepo && selectedBranch) {
      getRepositoryContents(token, selectedOwner.login, selectedRepo.name, selectedBranch)
        .then(setSolidityFiles)
        .catch(console.error);
    }
  }, [token, selectedOwner, selectedRepo, selectedBranch]);

  if (isLoading) {
    return (
      <div className="h-full bg-black text-white flex flex-col items-center justify-center">
        <div className="bg-[#222222] rounded-lg p-8 flex flex-col items-center">
          <Spinner size="lg" color="secondary" />
          <p className="mt-4 text-lg font-semibold">Loading</p>
          <p className="mt-2 text-sm text-gray-400">Please wait while we analyze your code.</p>
        </div>
      </div>
    );
  }

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    } else {
      router.push("/dashboard");
    }
  };

  return (
    <Card className="h-full">
      <CardHeader className="p-4 flex justify-between items-center border-t border-b border-gray-800">
        <div className="text-sm text-gray-400 flex">
          Dashboard <div className="mx-2">/</div> <div className="text-white">Scan Code</div>
        </div>
        <div>
          <Button className="mr-2" onClick={handleBack} disabled={currentStep === 1}>
            Go Back
          </Button>
          <Button
            color="secondary"
            className="bg-[#8B5CF6]"
            disabled={!isNextEnabled}
            endContent={<ArrowRight size={20} />}
            onClick={handleScan}
          >
            {currentStep === steps.length ? "Scan Code" : "Next"}
          </Button>
        </div>
      </CardHeader>

      <main className="flex-grow p-8">
        <div className="flex justify-center mb-12">
          {steps.map((step, index) => (
            <div key={step.label} className="flex items-center">
              <div
                className={`w-12 h-12 rounded-full flex items-center justify-center ${
                  index + 1 === currentStep ? "text-red-500" : "text-gray-400"
                }`}
              >
                {index + 1 < currentStep
                  ? step.selectedIcon
                  : index + 1 === currentStep
                    ? step.selectingIcon
                    : step.notSelectedIcon}
              </div>
              <span className={`mx-2 text-sm ${index + 1 === currentStep ? "text-[#C9A9E9]" : "text-gray-400"}`}>
                {step.label}
              </span>
              {index < steps.length - 1 && <div className="w-16 h-px bg-gray-700 mx-2" />}
            </div>
          ))}
        </div>

        <div className="max-w-2xl mx-auto mt-4">
          {currentStep === 1 && (
            <>
              <div className="mb-6 text-color-red">
                <Select
                  variant="bordered"
                  label={
                    <>
                      Git Organization
                      <span style={{ color: "red", marginLeft: "4px" }}>*</span>
                    </>
                  }
                  placeholder="Select one"
                  labelPlacement="outside"
                  className="w-full "
                  onSelectionChange={(keys) => {
                    const selected = Array.from(keys)[0] as string;
                    setSelectedOwner(owners.find((owner) => owner.login === selected) || null);
                    setSelectedRepo(null);
                    setSolidityFiles([]);
                  }}
                >
                  {owners.map((org) => (
                    <SelectItem
                      key={org.login}
                      value={org.login}
                      className="hover:bg-[#4F46E5] transition-colors duration-300"
                    >
                      {org.login}
                    </SelectItem>
                  ))}
                </Select>
              </div>
              {selectedOwner ? (
                <div className="mb-6">
                  <Autocomplete
                    variant="bordered"
                    label={
                      <>
                        Git Repository
                        <span style={{ color: "red", marginLeft: "4px" }}>*</span>
                      </>
                    }
                    labelPlacement="outside"
                    placeholder="Search a repository"
                    className="w-full className='hover:bg-[#4F46E5] transition-colors duration-300'"
                    onSelectionChange={(key) => {
                      const selected = key as string;
                      setSelectedRepo(repositories.find((repo) => repo.name === selected) || null);
                    }}
                  >
                    {repositories.map((repo) => (
                      <AutocompleteItem
                        key={repo.name}
                        value={repo.name}
                        className="hover:bg-[#4F46E5] transition-colors duration-300"
                      >
                        {repo.name}
                      </AutocompleteItem>
                    ))}
                  </Autocomplete>
                </div>
              ) : (
                <div className="mb-6">
                  <label className="block text-sm font-medium mb-2 text-left">
                    Git Repository
                    <span style={{ color: "red", marginLeft: "4px" }}>*</span>
                  </label>
                  <div className="bg-[#222222] rounded p-8 flex flex-col items-center justify-center text-center">
                    <p className="text-sm text-gray-400">
                      <Image
                        src="/empty_repository.svg"
                        alt="Empty Repository"
                        width={55}
                        height={55}
                        className="m-auto mb-4"
                      />
                      Repository would appear here,
                      <br />
                      after selecting the organization.
                    </p>
                  </div>
                </div>
              )}
            </>
          )}

          {currentStep === 2 && (
            <div className="mb-6">
              <Autocomplete
                variant="bordered"
                label="Select Branch"
                labelPlacement="outside"
                placeholder="Search branch"
                startContent={<Image src="/search.svg" alt="Branch" width={12} height={12} />}
                className="w-full"
                onSelectionChange={(keys) => {
                  const selected = keys as string;
                  setSelectedBranch(selected);
                }}
              >
                {branches.map((branch) => (
                  <AutocompleteItem
                    key={branch}
                    value={branch}
                    className="hover:bg-[#4F46E5] transition-colors duration-300"
                  >
                    {branch}
                  </AutocompleteItem>
                ))}
              </Autocomplete>
            </div>
          )}

          {currentStep === 3 && (
            <>
              <div className="mb-4">
                <Input
                  isClearable={true}
                  placeholder="Search contracts..."
                  value={contractSearch}
                  onChange={(e) => setContractSearch(e.target.value)}
                  onClear={() => setContractSearch("")}
                  startContent={<Image src="/search.svg" alt="Search" width={16} height={16} />}
                />
              </div>

              <div className="overflow-auto max-h-60">
                <Table
                  aria-label="Solidity files table"
                  selectionMode="multiple"
                  selectedKeys={new Set(selectedContracts)}
                  onSelectionChange={(selection) => setSelectedContracts(Array.from(selection) as string[])}
                >
                  <TableHeader>
                    <TableColumn>NAME</TableColumn>
                    <TableColumn>PATH</TableColumn>
                  </TableHeader>
                  <TableBody
                    emptyContent={
                      <div className="flex flex-col items-center">
                        <Image
                          src="/empty_contract.svg"
                          alt="No contracts found"
                          width={100}
                          height={100}
                          className="mt-8"
                        />
                        <p className="mt-2 text-gray-500">No contracts found</p>
                      </div>
                    }
                  >
                    {filteredSolidityFiles.map((file) => (
                      <TableRow key={file.path}>
                        <TableCell>{file.name}</TableCell>
                        <TableCell>{file.path}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </>
          )}
        </div>
      </main>
    </Card>
  );
};

export default ScanStepper;
